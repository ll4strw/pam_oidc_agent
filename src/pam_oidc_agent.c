/* # Copyright (C) 2024  ll4strw <l.lenoci@science.leidenuniv.nl> */

/* # This file is part of pam_oidc_agent */

/* # pam_oidc_agent.c is free software: Permission is hereby granted, */
/* # free of charge, to any person obtaining a copy */
/* # of this software and associated documentation files (the "Software"), to deal */
/* # in the Software without restriction, including without limitation the rights */
/* # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell */
/* # copies of the Software, and to permit persons to whom the Software is */
/* # furnished to do so, subject to the following conditions: */

/* # The above copyright notice and this permission notice shall be included in all */
/* # copies or substantial portions of the Software. */

/* # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR */
/* # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, */
/* # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE */
/* # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER */
/* # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, */
/* # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE */
/* # SOFTWARE. */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>



#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <oidc-agent/api.h>
#include <oidc-agent/oidc_error.h>



#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD



PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,  int flags,  int argc,  const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,  int flags,  int argc,  const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,  int flags,  int argc,  const char **argv) {
  return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,  int flags,  int argc,  const char **argv) {
  return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

// auth hook
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv) {

  char* username=NULL;
  const void *pamuser;
  
  struct agent_response response =
    getAgentTokenResponse("keycloak", 60, NULL,"pammy", NULL);
  if(response.type == AGENT_RESPONSE_TYPE_ERROR) {
    return PAM_AUTH_ERR;
  } else {
    
    struct token_response tok_res = response.token_response;

    unsigned long long now = time(NULL);

    pam_info (pamh, "%s", "Token expiration: ");
    pam_info (pamh, "%lu\n", tok_res.expires_at);

    if (tok_res.expires_at <= now){
      pam_info (pamh, "%s\n", "EXPIRED!!");
      return PAM_AUTH_ERR;
    }
    
  }
  secFreeAgentResponse(response);
  
  return PAM_SUCCESS;
}
