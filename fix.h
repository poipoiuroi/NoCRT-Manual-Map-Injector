#pragma once
#ifndef _FIX_H_
#define _FIX_H_

#include "globals.h"

#pragma function(memset)
void* memset(void* dest, int value, size_t num)
{
	__stosb(static_cast<unsigned char*>(dest), static_cast<unsigned char>(value), num);
	return dest;
}

#pragma function(memcpy)
void* memcpy(void* dest, const void* src, size_t num)
{
	__movsb(static_cast<unsigned char*>(dest), static_cast<const unsigned char*>(src), num);
	return dest;
}

#pragma function(wcscpy)
wchar_t* wcscpy(wchar_t* dest, const wchar_t* src)
{
	wchar_t* temp = dest;
	while (*src) *temp++ = *src++;
	*temp = L'\0';
	return dest;
}

#pragma function(wcscat)
wchar_t* wcscat(wchar_t* dest, const wchar_t* src) 
{
	wchar_t* temp = dest;
	while (*temp) temp++;
	while (*src) *temp++ = *src++;
	*temp = L'\0';
	return dest;
}

#pragma function(wcslen)
size_t wcslen(wchar_t const* str)
{
	size_t length = 0;
	while (str[length] != L'\0') length++;
	return length;
}

#pragma function(wcsstr)
wchar_t const* wcsstr(wchar_t const* haystack, wchar_t const* needle)
{
	if (*needle == L'\0')
	{
		return (wchar_t*)haystack;
	}

	for (const wchar_t* h = haystack; *h != L'\0'; ++h)
	{
		const wchar_t* p = h;
		const wchar_t* n = needle;
		while (*p == *n && *n != L'\0') { ++p; ++n; }
		if (*n == L'\0') return (wchar_t*)h;
	}
	return nullptr;
}

#pragma function(tolower)
wchar_t tolower(wchar_t c)
{
	if (c >= L'A' && c <= L'Z') return c + (L'a' - L'A');
	return c;
}

#pragma function(strcmp)
int strcmp(char const* str1, char const* str2)
{
	while (*str1 && (*str1 == *str2)) { ++str1; ++str2; }
	return (unsigned char)*str1 - (unsigned char)*str2;
}

#endif