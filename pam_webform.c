/**********************************************************************
| pam_webform 
| Version 0.1-rc1
| 
| A PAM to login to any webform 
| 
| Author: D.J. Capelis
| 
**********************************************************************/

#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>
#include<pwd.h>
#include<errno.h>

#include<curl/curl.h>

#include<pam_appl.h>

#define PAM_SM_AUTH
#include<pam_modules.h>

void chk_pamerr(int chk, pam_handle_t * pamh, void * free0, void * free1, void * free2);
void chk_err(void * check, void * free0, void * free1, void * free2);

#define BUF 1024
#define chk_err(cond) if(cond) { goto err; }

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * apph, int flags, int argc, const char ** argv)
{
    /* Part I - Initial checks */
    struct passwd * user;
    struct passwd pwent;
    char * pwentchars;
    char * uname;
    char * passprompt = "Password:";
    int ret;
    int pwentcharsmax = sysconf(_SC_GETPW_R_SIZE_MAX);
    int i;

    for(i=0; i<argc;++i)
    {   //DOARGS
/*
        if(!strncmp(argv[i], "stack", 6))
            stack = 1;
        if(!strncmp(argv[i], "unique", 7))
            unique = 1;
        if(!strncmp(argv[i], "norootok", 9))
            norootok = 1;
*/
    }

    pwentchars = calloc(1, pwentcharsmax);
    chk_err(pwentchars == NULL);

    ret = pam_get_user(apph, (const char **) &uname, NULL);
    chk_err(ret != PAM_SUCCESS);

    ret = getpwnam_r(uname, &pwent, pwentchars, pwentcharsmax, &user);
    chk_err(ret != NULL);

    //printf("User: %s Homedir: %s ID: %d\n", user->pw_name, user->pw_dir, user->pw_uid);

    struct pam_conv * pam_conv;
    struct pam_response * pam_resp;
    struct pam_message * pam_msg;
    struct pam_response presp;
    struct pam_message pmsg;

    pam_resp = &presp;
    pam_msg = &pmsg;
    pmsg.msg_style = PAM_PROMPT_ECHO_OFF;
    pmsg.msg = "password: ";

    ret = pam_get_item(apph, PAM_CONV, (void *) &pam_conv);
    chk_err(ret != PAM_SUCCESS);

    pam_conv->conv(1, (const struct pam_message **) &pam_msg, &pam_resp, pam_conv->appdata_ptr);
    //printf("Password: %s\n", pam_resp->resp);












    free(pwentchars);

    return PAM_SUCCESS;

err:
    printf("Error thrown\n");
    if(!pwentchars)
        free(pwentchars);

    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(__attribute__ ((unused)) pam_handle_t * apph, __attribute__ ((unused)) int flags, __attribute__ ((unused)) int argc, __attribute__ ((unused)) const char ** argv)
{
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_webform_modstruct = {
    "pam_webform",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};

#endif
