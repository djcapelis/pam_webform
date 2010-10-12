# ########## Project setup ##########
PROJECT(pam_webform)
CMAKE_MINIMUM_REQUIRED(VERSION 2.4.5)

# ######### General setup ##########
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})

#Debugging
SET(CMAKE_VERBOSE_MAKEFILE off)

# Flags
SET(CMAKE_C_FLAGS "-O2 -Wall -Wextra")

# ########## pam_webform library ##########
# Sources:
SET(SRCS pam_webform.c )

# Headers:
SET(HDRS)

# Includes: 
if(EXISTS /usr/include/security/)
    INCLUDE_DIRECTORIES(/usr/include/security/)
endif(EXISTS /usr/include/security/)
if(EXISTS /usr/include/pam/)
    INCLUDE_DIRECTORIES(/usr/include/pam/)
endif(EXISTS /usr/include/pam/)

# Libraries:

# Target:
ADD_LIBRARY(pam_webform MODULE ${SRCS} ${HDRS})
target_link_libraries(pam_webform pam pam_misc curl)
set_target_properties(pam_webform PROPERTIES PREFIX "")

# Install:
if(EXISTS /lib64/security/)
    set(PAM_MODULES_LOCATION /lib64/security/)
elseif(EXISTS /lib/security/)
    set(PAM_MODULES_LOCATION /lib/security/)
elseif(EXISTS /usr/lib/security/)
    set(PAM_MODULES_LOCATION /usr/lib/security/)
elseif(EXISTS /usr/lib64/security/)
    set(PAM_MODULES_LOCATION /usr/lib64/security/)
elseif(EXISTS /lib64/pam/)
    set(PAM_MODULES_LOCATION /lib64/pam/)
elseif(EXISTS /lib/pam/)
    set(PAM_MODULES_LOCATION /lib/pam/)
elseif(EXISTS /usr/lib64/pam/)
    set(PAM_MODULES_LOCATION /usr/lib64/pam/)
elseif(EXISTS /usr/lib/pam/)
    set(PAM_MODULES_LOCATION /usr/lib/pam/)
else(EXISTS /lib64/security/)
    message(FATAL_ERROR "Cannot find the location of the pam_modules")
endif(EXISTS /lib64/security/)
find_path(PAM_MODULES_LOCATION pam_deny.so /lib64/security /lib/security /usr/lib64/security /usr/lib/security /lib64/pam /lib/pam /usr/lib64/pam /usr/lib/pam)
INSTALL(TARGETS pam_webform DESTINATION ${PAM_MODULES_LOCATION})
