// @flow strict
import * as React from 'react';
import * as Immutable from 'immutable';
import URI from 'urijs';
import { PluginStore } from 'graylog-web-plugin/plugin';

import type { LdapBackend, LdapCreate } from 'logic/authentication/ldap/types';
import AuthenticationDomain from 'domainActions/authentication/AuthenticationDomain';
import { DocumentTitle, Spinner } from 'components/common';

import { AUTH_BACKEND_META } from './BackendCreate';
import WizardPageHeader from './WizardPageHeader';

import type { WizardFormValues } from '../BackendWizard/contexts/BackendWizardContext';
import BackendWizard from '../BackendWizard';

type Props = {
  authenticationBackend: LdapBackend,
  initialStepKey: ?string,
};

export const prepareInitialValues = ({
  defaultRoles = Immutable.List(),
  config: {
    serverUrls = [],
    systemUserDn,
    transportSecurity,
    userFullNameAttribute,
    userNameAttribute,
    userSearchBase,
    userSearchPattern,
    verifyCertificates,
  },
}: LdapBackend): WizardFormValues => {
  const serverUrl = new URI(serverUrls[0]);

  return {
    defaultRoles: defaultRoles.join(),
    serverUrlHost: serverUrl.hostname(),
    serverUrlPort: serverUrl.port(),
    systemUserDn,
    transportSecurity,
    userFullNameAttribute,
    userNameAttribute,
    userSearchBase,
    userSearchPattern,
    verifyCertificates,
  };
};

export const passwordUpdatePayload = (systemUserPassword: ?string) => {
  // Only update password on edit if necessary,
  // if a users resets the previously defined password its form value is an empty string
  if (systemUserPassword === undefined) {
    return { keep_value: true };
  }

  if (systemUserPassword === '') {
    return { delete_value: true };
  }

  return { set_value: systemUserPassword };
};

const _optionalWizardProps = (initialStepKey: ?string) => {
  const props = {};

  if (initialStepKey) {
    props.initialStepKey = initialStepKey;
  }

  return props;
};

export const handleSubmit = (payload: LdapCreate, formValues: WizardFormValues, backendId: string, backendAlreadyHasGroupSync: boolean, serviceType: string) => {
  const authGroupSyncPlugins = PluginStore.exports('authentication.enterprise.ldap.groupSync');
  const groupSyncActions = authGroupSyncPlugins?.[0]?.actions;

  return AuthenticationDomain.update(backendId, {
    ...payload,
    id: backendId,
    config: {
      ...payload.config,
      system_user_password: passwordUpdatePayload(payload.config.system_user_password),
    },
  }).then((result) => {
    if (result) {
      // Create group sync config
      if (backendAlreadyHasGroupSync && formValues.synchronizeGroups && groupSyncActions?.handleUpdate) {
        return groupSyncActions.handleUpdate(formValues, backendId, serviceType);
      }

      // Update group sync config
      if (!backendAlreadyHasGroupSync && formValues.synchronizeGroups && groupSyncActions?.handleUpdate) {
        return groupSyncActions.handleCreate(formValues, backendId, serviceType);
      }

      // Delete existing group sync config
      if (backendAlreadyHasGroupSync && !formValues.synchronizeGroups && groupSyncActions?.delete) {
        return groupSyncActions.delete(backendId);
      }
    }

    return result;
  });
};

const BackendEdit = ({ authenticationBackend, initialStepKey }: Props) => {
  const authGroupSyncPlugins = PluginStore.exports('authentication.enterprise.ldap.groupSync');
  const hasGroupSyncPlugin = !!authGroupSyncPlugins?.[0];
  const authBackendMeta = {
    ...AUTH_BACKEND_META,
    backendId: authenticationBackend.id,
    backendHasPassword: authenticationBackend.config.systemUserPassword.isSet,
  };
  let initialValues = prepareInitialValues(authenticationBackend);

  if (hasGroupSyncPlugin) {
    const {
      initialValues: initialGroupSyncValues,
      finishedLoading,
    } = authGroupSyncPlugins?.[0]?.hooks?.useInitialGroupSyncValues(authenticationBackend.id);

    if (!finishedLoading) {
      return <Spinner />;
    }

    initialValues = { ...initialValues, ...initialGroupSyncValues };
  }

  const _handleSubmit = (payload, formValues) => handleSubmit(payload, formValues, authBackendMeta.backendId, !!initialValues.synchronizeGroups, authBackendMeta.serviceType);

  return (
    <DocumentTitle title="Edit LDAP Authentication Service">
      <WizardPageHeader authenticationBackend={authenticationBackend} />
      <BackendWizard {..._optionalWizardProps(initialStepKey)}
                     authBackendMeta={authBackendMeta}
                     initialValues={initialValues}
                     onSubmit={_handleSubmit} />
    </DocumentTitle>
  );
};

export default BackendEdit;
