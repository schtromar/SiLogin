// libsilogin.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"
#include "libsilogin.h"

// TODO: This is an example of a library function
void fnlibsilogin()
{
}

static int two() {
	return 5;
}

int silogin::two()
{
	return ::two();
}
