NAME=jiraRESTbridge
VERSION=1.1.1
RELEASE=2
SOURCE=$(NAME)-$(VERSION).tar.gz
EXES=jiraRESTbridge.cgi
LIBS=Jira_OAuth.pm
CONFS=jirarestbridge_log4perl.conf jiraRESTbridge.conf
ARCH=noarch
# PREFIX=/var/www/jiraRESTbridge
CLEAN_TARGETS=$(SPEC) $(NAME)-$(VERSION) $(SOURCE) # for in-house package

include $(shell starter)/rules.mk
