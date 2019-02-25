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

/*** buffer ***/

typedef struct {
	const void *data;
	unsigned char *pos;
	uint32_t size;
} buffer_t;

static JSON_INLINE void read_buffer(buffer_t *buffer, void *destination, size_t size) {
	memcpy(destination, buffer->pos, size);
	/*(unsigned char*)*/buffer->pos += size;
}

static int buffer_init(buffer_t *buffer, const void *data)
{
	buffer->data = data;
	buffer->pos = (void *)data;
	read_buffer(buffer, &buffer->size, sizeof(uint32_t));
	return 0;
}

/*** deserializer ***/

static json_t *read_value(buffer_t *buffer, json_error_t *error);
static bos_data_type read_data_type(buffer_t *buffer);
static json_t *read_data(buffer_t *buffer, bos_data_type data_type, json_error_t *error);


static json_t *read_bool(buffer_t *buffer) {
	uint8_t number;
	read_buffer(buffer, &number, sizeof(uint8_t));
	return number == 0 ? json_false() : json_true();
}

static json_t *read_int8(buffer_t *buffer) {
	int8_t number;
	read_buffer(buffer, &number, sizeof(int8_t));
	return json_integer((json_int_t)number);
}

static json_t *read_int16(buffer_t *buffer) {
	int16_t number;
	read_buffer(buffer, &number, sizeof(int16_t));
	return json_integer((json_int_t)number);
}

static json_t *read_int32(buffer_t *buffer) {
	int32_t number;
	read_buffer(buffer, &number, sizeof(int32_t));
	return json_integer((json_int_t)number);
}

static json_t *read_int64(buffer_t *buffer) {
	int64_t number;
	read_buffer(buffer, &number, sizeof(int64_t));
	return json_integer((json_int_t)number);
}

static json_t *read_uint8(buffer_t *buffer) {
	uint8_t number;
	read_buffer(buffer, &number, sizeof(uint8_t));
	return json_integer((json_int_t)number);
}

static json_t *read_uint16(buffer_t *buffer) {
	uint16_t number;
	read_buffer(buffer, &number, sizeof(uint16_t));
	return json_integer((json_int_t)number);
}

static json_t *read_uint32(buffer_t *buffer) {
	uint32_t number;
	read_buffer(buffer, &number, sizeof(uint32_t));
	return json_integer((json_int_t)number);
}

static json_t *read_uint64(buffer_t *buffer) {
	int64_t number;
	read_buffer(buffer, &number, sizeof(uint64_t));
	return json_integer((json_int_t)number);
}

static size_t read_uvarint(buffer_t *buffer) {

	uint8_t type_flag;
	uint64_t le64;
	uint32_t le32;
	uint16_t le16;

	read_buffer(buffer, &type_flag, sizeof(uint8_t));

	switch (type_flag) {
	case 0xFF:
		read_buffer(buffer, &le64, sizeof(uint64_t));
		return (size_t)le64;

	case 0xFE:
		read_buffer(buffer, &le32, sizeof(uint32_t));
		return (size_t)le32;

	case 0xFD:
		read_buffer(buffer, &le16, sizeof(uint16_t));
		return (size_t)le16;

	default:
		return (size_t)type_flag;
	}
}

static json_t *read_real32(buffer_t *buffer) {
	float number;
	read_buffer(buffer, &number, sizeof(float));
	return json_real((double)number);
}

static json_t *read_real64(buffer_t *buffer) {
	double number;
	read_buffer(buffer, &number, sizeof(double));
	return json_real(number);
}

static char *read_raw_string(buffer_t *buffer) {

	size_t len = read_uvarint(buffer);

	if (len > 0) {
		char *utf8String = (char*)jsonp_malloc(sizeof(char) * len + 1);
		read_buffer(buffer, utf8String, sizeof(char) * len);
		memset(utf8String + len, (char)0, sizeof(char));
		return utf8String;
	}
	else {
		return "";
	}
}

static json_t *read_string(buffer_t *buffer) {
	char *str = read_raw_string(buffer);
	json_t *ret = json_string(str);
	free(str);
	return ret;
}

static json_t *read_bytes(buffer_t *buffer) {

	size_t len = read_uvarint(buffer);
	void *bytes = jsonp_malloc(len);
	read_buffer(buffer, bytes, len);
	return json_bytes(bytes, len);
}

static json_t *read_array(buffer_t *buffer, json_error_t *error) {

	size_t len = read_uvarint(buffer);
	json_array_t *array = json_to_array(json_array());

	for (unsigned int i = 0; i < len; ++i) {
		json_t *entry = read_value(buffer, error);
		if (entry == NULL)
			return NULL;

		json_array_append(&array->json, entry);
	}

	return &array->json;
}

static json_t *read_obj(buffer_t *buffer, json_error_t *error) {

	size_t len = read_uvarint(buffer);
	json_object_t *object = json_to_object(json_object());

	for (unsigned int i = 0; i < len; ++i) {

		char *key = read_raw_string(buffer);
		json_t *entry = read_value(buffer, error);
		if (entry == NULL)
			return NULL;

		json_object_set(&object->json, key, entry);
		free(key);
	}

	return &object->json;
}

static json_t *read_value(buffer_t *buffer, json_error_t *error) {
	bos_data_type data_type = read_data_type(buffer);
	return read_data(buffer, data_type, error);
}

static bos_data_type read_data_type(buffer_t *buffer) {

	uint8_t type;
	read_buffer(buffer, &type, sizeof(uint8_t));

	if (type > 0x0F) {
		return BOS_NULL;
	}

	return (bos_data_type)type;
}

static json_t *read_data(buffer_t *buffer, bos_data_type data_type, json_error_t *error) {
	switch (data_type) {
	case BOS_NULL:
		return json_null();
	case BOS_BOOL:
		return read_bool(buffer);
	case BOS_INT8:
		return read_int8(buffer);
	case BOS_INT16:
		return read_int16(buffer);
	case BOS_INT32:
		return read_int32(buffer);
	case BOS_INT64:
		return read_int64(buffer);
	case BOS_UINT8:
		return read_uint8(buffer);
	case BOS_UINT16:
		return read_uint16(buffer);
	case BOS_UINT32:
		return read_uint32(buffer);
	case BOS_UINT64:
		return read_uint64(buffer);
	case BOS_FLOAT:
		return read_real32(buffer);
	case BOS_DOUBLE:
		return read_real64(buffer);
	case BOS_STRING:
		return read_string(buffer);
	case BOS_BYTES:
		return read_bytes(buffer);
	case BOS_ARRAY:
		return read_array(buffer, error);
	case BOS_OBJ:
		return read_obj(buffer, error);
	default:
		error_set(error, json_error_invalid_format, "invalid data_type");
		return NULL;
	}
}

json_t *bos_deserialize(const void *data, json_error_t *error) {

	buffer_t *buffer = jsonp_malloc(sizeof(buffer_t));
	buffer_init(buffer, data);
	jsonp_error_init(error, "<bos_deserialize>");

	if (buffer->size < 5) {
		error_set(error, json_error_invalid_format, "size too small to be valid");
		return NULL;
	}

	return read_value(buffer, error);
}

int bos_validate(const void *data, size_t size) {

	uint32_t data_size;

	if (data == NULL)
		return 0/*false*/;

	if (size < 5)
		return FALSE;

	memcpy(&data_size, data, sizeof(uint32_t));
	if (size < data_size)
		return FALSE;

	return TRUE;
}

unsigned int bos_sizeof(const void *data) {

	uint32_t data_size;

	if (data == NULL)
		return 0;

	memcpy(&data_size, data, sizeof(uint32_t));

	return data_size;
}