# Copyright (C) 2024  ll4strw <l.lenoci@science.leidenuniv.nl>

# This file is part of pam_oidc_agent

# configure.ac is free software: Permission is hereby granted,
# free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


AC_INIT([pam_oidc-agent],[0.1], [l.lenoci@science.leidenuniv.nl])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AM_PROG_AR
LT_INIT([disable-static])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# headers checks
AC_CHECK_HEADERS([sodium.h],[],
	[AC_MSG_ERROR([[libsodium headers not found.]])])

AC_CHECK_HEADERS([oidc-agent/api.h],[],
	[AC_MSG_ERROR([[oidc-agent headers not found.]])])

	
AC_CHECK_HEADERS([security/pam_appl.h security/pam_modules.h security/pam_ext.h], [],
	[AC_MSG_ERROR([[pam headers not found.]])])     


# libs checks
AC_CHECK_LIB(sodium, crypto_auth_keybytes,[],
		  [AC_MSG_ERROR([[sodium lib not found.]])])
AC_CHECK_LIB(oidc-agent, getAgentTokenResponse,[],
		  [AC_MSG_ERROR([[oidc-agent lib not found.]])])
AC_CHECK_LIB(pam, pam_get_item,[],
		  [AC_MSG_ERROR([[pam lib not found.]])])		  

# custom pam module dir option
AC_SUBST(PAMDIR, "\$(exec_prefix)/lib64/security")
AC_ARG_WITH(pam-mod-dir,
	AS_HELP_STRING([--with-pam-mod-dir=DIR],
	[Where to install PAM module [[PREFIX/lib64/security]]]),
	[case "${withval}" in
	/*) PAMDIR="${withval}";;
	./*|../*) AC_MSG_ERROR(Bad value for --with-pam-mod-dir);;
	*)  PAMDIR="\$(exec_prefix)/lib64/${withval}";;
	esac])


AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT
