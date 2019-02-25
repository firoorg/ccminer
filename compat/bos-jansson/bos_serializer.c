/*
* Copyright (c) 2018 JCThePants <github.com/JCThePants>
*
* Bos-Jansson is free software; you can redistribute it and/or modify
* it under the terms of the MIT license. See LICENSE for details.
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "jansson_private.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif


#include "bosjansson.h"
#include "strbuffer.h"
#include "utf.h"

/*** error reporting ***/

static void error_set(json_error_t *error, enum json_error_code code, const char *msg, ...)
{
	va_list ap;
	char msg_text[JSON_ERROR_TEXT_LENGTH];

	const char *result = msg_text;

	if (!error)
		return;

	va_start(ap, msg);
	vsnprintf(msg_text, JSON_ERROR_TEXT_LENGTH, msg, ap);
	msg_text[JSON_ERROR_TEXT_LENGTH - 1] = '\0';
	va_end(ap);

	jsonp_error_set(error, -1, -1, 0, code, "%s", result);
}

/*** buffer **/

typedef struct {
	void *data;
	unsigned char *pos;
	size_t size; // size of data
	size_t allocated; // size of allocated memory
} buffer_t;

static int write_value(json_t *value, buffer_t *buffer, json_error_t *error);

static int ensure_buffer_size(buffer_t *buffer, size_t amount, json_error_t *error)
{
	void *old_data = buffer->data;
	size_t new_size = max(buffer->size + amount, buffer->size * 2);

	if (buffer->size + amount <= buffer->allocated)
		return TRUE;

	buffer->data = jsonp_malloc(new_size * sizeof(uint8_t));
	/*buffer->data = realloc(buffer->data, new_size * sizeof(uint8_t)); */
	if (!buffer->data) {
		error_set(error, json_error_out_of_memory, "failed to allocate additional buffer memory");
		return FALSE;
	}

	buffer->allocated = new_size;
	buffer->pos = (unsigned char*)buffer->data + buffer->size;
	memcpy(buffer->data, old_data, buffer->size);
	jsonp_free(old_data);
	return TRUE;
}

static JSON_INLINE int write_buffer(buffer_t *buffer, const void *source, size_t len, json_error_t *error) {
	if (!ensure_buffer_size(buffer, buffer->size + len, error))
		return FALSE;
	memcpy(buffer->pos, source, len);
	/*(unsigned char*)*/buffer->pos += len;
	buffer->size += len;
	return TRUE;
}

static JSON_INLINE int write_buffer_byte(buffer_t *buffer, int value, json_error_t *error) {
	if (!ensure_buffer_size(buffer, buffer->size + 1, error))
		return FALSE;
	*((uint8_t *)buffer->pos) = (uint8_t)value;
	/*(unsigned char*)*/buffer->pos += 1;
	buffer->size += 1;
	return TRUE;
}

static int buffer_init(buffer_t *buffer)
{
	buffer->data = jsonp_malloc(1024);
	buffer->pos = buffer->data;
	buffer->size = 0;
	buffer->allocated = 1024;
	return 0;
}

static bos_data_type get_data_type(json_t *value) {

	if (json_is_object(value))
		return BOS_OBJ;

	if (json_is_null(value))
		return BOS_NULL;

	if (json_is_boolean(value))
		return BOS_BOOL;

	if (json_is_string(value))
		return BOS_STRING;

	if (json_is_number(value)) {

		if (json_is_integer(value)) {

			json_int_t integer = json_to_integer(value)->value;

			if (integer < 0) {

				if (integer >= -128)
					return BOS_INT8;

				if (integer >= -32768)
					return BOS_INT16;

				if (integer >= -2147483648)
					return BOS_INT32;

				return BOS_INT64;
			}

			if (integer <= 255)
				return BOS_UINT8;

			if (integer <= 65535)
				return BOS_UINT16;

			if (integer <= 4294967295)
				return BOS_UINT32;

			return BOS_UINT64;
		}
		else {
			return BOS_FLOAT;
		}
	}

	if (json_is_array(value))
		return BOS_ARRAY;

	if (json_is_bytes(value))
		return BOS_BYTES;

	return BOS_NULL;
}

/*** serializer ***/

static int write_null(buffer_t *buffer, json_error_t *error) {
	return write_buffer_byte(buffer, 0, error);
}

static int write_bool(json_t *value, buffer_t *buffer, json_error_t *error) {
	if (!write_buffer_byte(buffer, BOS_BOOL, error)) return FALSE;
	if (!write_buffer_byte(buffer, json_is_true(value) ? (uint8_t)1 : (uint8_t)0, error)) return FALSE;
	return TRUE;
}

static int write_int8(json_t *value, buffer_t *buffer, json_error_t *error) {
	if (!write_buffer_byte(buffer, BOS_INT8, error)) return FALSE;
	if (!write_buffer_byte(buffer, (int8_t)json_to_integer(value)->value, error)) return FALSE;
	return TRUE;
}

static int write_int16(json_t *value, buffer_t *buffer, json_error_t *error) {
	int16_t integer = (int16_t)json_to_integer(value)->value;
	if (!write_buffer_byte(buffer, BOS_INT16, error)) return FALSE;
	if (!write_buffer(buffer, &integer, 2, error)) return FALSE;
	return TRUE;
}

static int write_int32(json_t *value, buffer_t *buffer, json_error_t *error) {
	int32_t integer = (int32_t)json_to_integer(value)->value;
	if (!write_buffer_byte(buffer, BOS_INT32, error)) return FALSE;
	if (!write_buffer(buffer, &integer, 4, error)) return FALSE;
	return TRUE;
}

static int write_int64(json_t *value, buffer_t *buffer, json_error_t *error) {
	int64_t integer = (int64_t)json_to_integer(value)->value;
	if (!write_buffer_byte(buffer, BOS_INT64, error)) return FALSE;
	if (!write_buffer(buffer, &integer, 8, error)) return FALSE;
	return TRUE;
}

static int write_uint8(json_t *value, buffer_t *buffer, json_error_t *error) {
	uint8_t integer = (uint8_t)json_to_integer(value)->value;
	if (!write_buffer_byte(buffer, BOS_UINT8, error)) return FALSE;
	if (!write_buffer(buffer, &integer, 1, error)) return FALSE;
	return TRUE;
}

static int write_uint16(json_t *value, buffer_t *buffer, json_error_t *error) {
	uint16_t integer = (uint16_t)json_to_integer(value)->value;
	if (!write_buffer_byte(buffer, BOS_UINT16, error)) return FALSE;
	if (!write_buffer(buffer, &integer, 2, error)) return FALSE;
	return TRUE;
}

static int write_uint32(json_t *value, buffer_t *buffer, json_error_t *error) {
	uint32_t integer = (uint32_t)json_to_integer(value)->value;
	if (!write_buffer_byte(buffer, BOS_UINT32, error)) return FALSE;
	if (!write_buffer(buffer, &integer, 4, error)) return FALSE;
	return TRUE;
}

static int write_uint64(json_t *value, buffer_t *buffer, json_error_t *error) {
	uint64_t integer = (uint64_t)json_to_integer(value)->value;
	if (!write_buffer_byte(buffer, BOS_UINT64, error)) return FALSE;
	if (!write_buffer(buffer, &integer, 8, error)) return FALSE;
	return TRUE;
}

static int write_uvarint(unsigned int value, buffer_t *buffer, json_error_t *error) {

	if (value < 0xFD) {
		uint8_t integer8 = (uint8_t)value;
		if (!write_buffer(buffer, &integer8, 1, error)) return FALSE;

	}
	else if (value <= 0xFFFF) {

		uint16_t integer16 = (uint16_t)value;
		if (!write_buffer_byte(buffer, 0xFD, error)) return FALSE;
		if (!write_buffer(buffer, &integer16, 2, error)) return FALSE;

	}
	else if (value <= 0xFFFFFFFF) {

		uint32_t integer32 = (uint32_t)value;
		if (!write_buffer_byte(buffer, 0xFE, error)) return FALSE;
		if (!write_buffer(buffer, &integer32, 4, error)) return FALSE;

	}
	else {

		uint64_t integer64 = (uint64_t)value;
		if (!write_buffer_byte(buffer, 0xFF, error)) return FALSE;
		if (!write_buffer(buffer, &integer64, 8, error)) return FALSE;
	}
	return TRUE;
}

static int write_real32(json_t *value, buffer_t *buffer, json_error_t *error) {
	float real = (float)json_to_real(value)->value;
	if (!write_buffer_byte(buffer, BOS_FLOAT, error)) return FALSE;
	if (!write_buffer(buffer, &real, 4, error)) return FALSE;
	return TRUE;
}

static int write_real64(json_t *value, buffer_t *buffer, json_error_t *error) {
	double real = json_to_real(value)->value;
	if (!write_buffer_byte(buffer, BOS_DOUBLE, error)) return FALSE;
	if (!write_buffer(buffer, &real, 8, error)) return FALSE;
	return TRUE;
}

static int write_string(json_t *value, buffer_t *buffer, json_error_t *error) {

	size_t len = json_string_length(value);
	const char *str = json_string_value(value);

	if (!write_buffer_byte(buffer, BOS_STRING, error)) return FALSE;
	if (!write_uvarint(len, buffer, error)) return FALSE;
	if (len > 0 && !write_buffer(buffer, str, len, error)) return FALSE;

	return TRUE;
}

static int write_key_string(const char *str, buffer_t *buffer, json_error_t *error) {

	size_t len = strlen(str);
	if (len > 255) {
		error_set(error, json_error_invalid_argument, "key string is too long");
		return FALSE;
	}

	if (!write_uvarint(len, buffer, error)) return FALSE;
	if (len > 0 && !write_buffer(buffer, str, len, error)) return FALSE;

	return TRUE;
}

static int write_bytes(json_t *value, buffer_t *buffer, json_error_t *error) {

	size_t len = json_bytes_size(value);

	if (!write_buffer_byte(buffer, BOS_BYTES, error)) return FALSE;
	if (!write_uvarint(len, buffer, error)) return FALSE;
	if (len > 0 && !write_buffer(buffer, json_bytes_value(value), len, error)) return FALSE;

	return TRUE;
}

static int write_array(json_t *value, buffer_t *buffer, json_error_t *error) {

	size_t len = json_array_size(value);

	if (!write_buffer_byte(buffer, BOS_ARRAY, error)) return FALSE;
	if (!write_uvarint(len, buffer, error)) return FALSE;

	if (len > 0) {
		for (unsigned int i = 0; i < len; ++i) {
			json_t *entry = json_array_get(value, i);
			if (!write_value(entry, buffer, error)) return FALSE;
		}
	}

	return TRUE;
}

static int write_obj(json_t *value, buffer_t *buffer, json_error_t *error) {

	size_t len = json_object_size(value);

	if (!write_buffer_byte(buffer, BOS_OBJ, error)) return FALSE;
	if (!write_uvarint(len, buffer, error)) return FALSE;

	if (len > 0) {
		void *iter = json_object_iter(value);
		for (unsigned int i = 0; i < len; ++i) {

			const char *key = json_object_iter_key(iter);
			json_t *entry_value = json_object_iter_value(iter);

			if (!write_key_string(key, buffer, error)) return FALSE;

			if (!write_value(entry_value, buffer, error)) return FALSE;

			iter = json_object_iter_next(value, iter);
		}
	}

	return TRUE;
}

static int write_value(json_t *value, buffer_t *buffer, json_error_t *error) {

	bos_data_type data_type = get_data_type(value);

	switch (data_type) {

	case BOS_NULL:
		return write_null(buffer, error);

	case BOS_BOOL:
		return write_bool(value, buffer, error);

	case BOS_INT8:
		return write_int8(value, buffer, error);

	case BOS_INT16:
		return write_int16(value, buffer, error);

	case BOS_INT32:
		return write_int32(value, buffer, error);

	case BOS_INT64:
		return write_int64(value, buffer, error);

	case BOS_UINT8:
		return write_uint8(value, buffer, error);

	case BOS_UINT16:
		return write_uint16(value, buffer, error);

	case BOS_UINT32:
		return write_uint32(value, buffer, error);

	case BOS_UINT64:
		return write_uint64(value, buffer, error);

	case BOS_FLOAT:
		return write_real32(value, buffer, error);

	case BOS_DOUBLE:
		return write_real64(value, buffer, error);

	case BOS_STRING:
		return write_string(value, buffer, error);

	case BOS_BYTES:
		return write_bytes(value, buffer, error);

	case BOS_ARRAY:
		return write_array(value, buffer, error);

	case BOS_OBJ:
		return write_obj(value, buffer, error);

	default:
		error_set(error, json_error_wrong_type, "invalid data_type");
		return FALSE;
	}
}

bos_t *bos_serialize(json_t *value, json_error_t *error) {

	uint32_t size;
	bos_t *result;

	buffer_t *buffer = jsonp_malloc(sizeof(buffer_t));
	buffer_init(buffer);
	jsonp_error_init(error, "<bos_serialize>");

	// leave room for data length integer which will be filled later
	/*(unsigned char*)*/buffer->pos += 4;
	buffer->size = 4;

	if (!write_value(value, buffer, error)) {
		jsonp_free(buffer);
		return NULL;
	}
	size = (uint32_t)buffer->size;
	/*
	buffer->pos = buffer->data;
	if (!write_buffer(buffer, &size, 4, error))
	return NULL;

	buffer->size -= 4; // remove extra 4 caused by writing the size to the beginning
	*/

	memcpy(buffer->data, &size, sizeof(uint32_t));
	result = (bos_t *)jsonp_malloc(sizeof(bos_t));
	result->data = buffer->data;
	result->size = buffer->size;

	jsonp_free(buffer);

	return result;
}

void bos_free(bos_t *ptr) {
	jsonp_free((void *)ptr->data);
	jsonp_free(ptr);
}