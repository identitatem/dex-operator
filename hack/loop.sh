#!/bin/bash

while true;
do
  date -u
  date
  make cleanup
  sleep 90
  make sdk-run
  sleep 30
  oc apply -f config/samples/auth_v1alpha1_dexserver.yaml
	sleep 30
	oc apply -f config/samples/dexclient-1000.yaml
	sleep 5
	oc apply -f config/samples/dexclient-1100.yaml
	sleep 5
	oc apply -f config/samples/dexclient-1200.yaml
  sleep 30
  oc get oauth2clients -A
  oc get oauth2clients -A | awk '{print $2}' | grep -v NAME | xargs -I % oc delete oauth2clients %
  echo "---------------------------"
done
