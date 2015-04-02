NAME=jirarestbridge
VERSION=1.1.2
<<<<<<< HEAD
RELEASE=2
=======
RELEASE=4
>>>>>>> 222ecdc4893d67f0f2e0adf6851514987e07dc2b
SOURCE=$(NAME)-$(VERSION).tar.gz
EXES=jiraRESTbridge.cgi
LIBS=Jira_OAuth.pm
CONFS=jirarestbridge_log4perl.conf jiraRESTbridge.conf
ARCH=all
# PREFIX=/var/www/jiraRESTbridge
CLEAN_TARGETS=$(SPEC) $(NAME)-$(VERSION) $(SOURCE) # for in-house package

include $(shell starter)/rules.mk
