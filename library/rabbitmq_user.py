#!/usr/bin/python

# (c) 2017, Giuseppe Pellegrino <mr.giuseppepellegrino@gmail.com>

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: rabbitmq_user
short_description: Manage RabbitMQ user
description:
  - Create, delete, update a RabbitMQ user and manage its permissions.
author: '"Giuseppe Pellegrino @joe-pll"'
options:
  login_host:
    description:
      - The RabbitMQ REST API endpoint host
    required: false
    default: localhost
  login_port:
    description:
      - The RabbitMQ REST API endpoint port
    required: false
    default: 15672
  login_user:
    description:
      - The user to authenticate with in RabbitMQ
     default: guest
     required: false
  login_password:
    description:
      - The password of the user that authenticate in RabbitMQ
     default: guest
     required: false
  name:
    description:
      - The name of the user
    required: true
    default: null
    aliases: [user]
  password:
    description:
      - The password for the new user
    required: false
    default: ''
  permissions:
    description:
      - A list of permissions
      - Each permission is a dictionary with vhost, configure_priv, write_priv, read_priv
      - The only required key is vhost, all the other default to '.*'
      - This option is preferable when all the permissions for a user must be set
      - When only the permission for a vhost matters then 'vhost' is preferred
  ssl_enabled:
    description:
      - Whether or not RabbitMQ is listening on HTTPS
    default: false
    required: false
  ssl_verify:
    description:
      - Whether or not there must be a SSL certificate verification
  state:
    description:
      - The state of user
    default: present
    choices: [present, absent]
  tags:
    description:
      - A comma separated list with RabbitMQ tags
    default: []
    required: false
  vhost:
    description:
      - The vhost for the user's privileges
      - Ignored when permissions is set
    default: null
    required: false
  configure_priv:
    description:
      - The configure privileges for the vhost
      - Ignored when permissions is set
    default: .*
    required: false
  read_priv:
    description:
      - The read privileges for the vhost
      - Ignored when permissions is set
    default: .*
    required: false
  write_priv:
    description:
      - The write privileges for the vhost
      - Ignored when ermissions is set
    default: .*
    required: false
'''

EXAMPLES = '''
# Ensure that the user 'another_user' exists and the vhost has the permissions
- rabbitmq_user:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: another_user
    password: user_pass
    state: present
    vhost: /test
    configure_priv: '.*alpha.*'

# Ensure that the user another_user has all the permissions
- rabbitmq_user:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: another_user
    password: user_pass
    state: present
    permissions:
      - vhost: /test
        configure_priv: '.*alpha.*'
      - vhost: /test2
        read_priv: '.*beta.*'

# Ensure that the user another_user is not present
- rabbitmq_user:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: another_user
    state: absent
'''

import urllib
from ansible.module_utils.rabbitmq_common import RabbitMQ


class RabbitMQUser(RabbitMQ):

    def __init__(self):
        self.arguments_spec = dict(
            configure_priv=dict(type='str', default='.*', required=False),
            name=dict(type='str', required=True, aliases=['user']),
            password=dict(type='str', required=False, default='', no_log=True),
            permissions=dict(type='list', default=[], required=False),
            read_priv=dict(type='str', default='.*', required=False),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            tags=dict(type='str', default='', required=False),
            vhost=dict(type='str', required=False),
            write_priv=dict(type='str', default='.*', required=False),
        )
        super(RabbitMQUser, self).__init__(
                                    derived_args_spec=self.arguments_spec,
                                    supports_check_mode=True)

    def _build_user_path(self):
        safe_name = urllib.quote(self.name, '')
        path = '/api/users/{name}'.format(name=safe_name)
        return path

    def _build_permission_path(self, vhost):
        safe_vhost = urllib.quote(vhost, '')
        safe_name = urllib.quote(self.name, '')
        path = '/api/permissions/{vhost}/{name}'.format(vhost=safe_vhost,
                                                        name=safe_name)
        return path

    def _list(self, path):
        request = self.rabbitmq_request('get', path=path)
        self.error_handling(request.status_code)
        return request.json()

    def list_vhosts(self):
        return self._list('/api/vhosts')

    def list_users(self):
        return self._list('/api/users')

    def list_user_permissions(self):
        return self._list(self._build_user_path() + '/permissions')

    def add_user(self):
        payload = dict(
            password=self.password,
            tags=self.tags.lower().strip().replace(' ', ''),
        )
        request = self.rabbitmq_request('put', path=self._build_user_path(),
                                        payload=payload)
        self.error_handling(request.status_code)

    def delete_user(self):
        request = self.rabbitmq_request('delete', path=self._build_user_path())
        self.error_handling(request.status_code)

    def add_permission(self, permission):
        vhost = permission['vhost']
        path = self._build_permission_path(vhost)
        payload = dict(
            configure=permission['configure'],
            read=permission['read'],
            write=permission['write'],
        )
        request = self.rabbitmq_request('put', path=path, payload=payload)
        self.error_handling(request.status_code)

    def delete_permission(self, permission):
        vhost = permission['vhost']
        path = self._build_permission_path(vhost)
        request = self.rabbitmq_request('delete', path=path)
        self.error_handling(request.status_code)

    def _check_password_changed(self, password):
        # TODO implement according to http://www.rabbitmq.com/passwords.html#computing-password-hash
        return True

    def _verify_permissions(self):
        vhosts = [v['name'] for v in self.list_vhosts()]
        for perm in self.permissions:
            if 'vhost' not in perm:
                self.fail('The permission does not have the vhost.')
            if perm['vhost'] not in vhosts:
                self.fail('Permissions cannot be assigned to an '
                          'undefined vhost `{}`'.format(perm['vhost']))

    def _match_permission(self, perm1, perm2):
        if perm1['vhost'] != perm2['vhost']:
            return False

        if (perm1['configure'] != perm2['configure'] or
                perm1['read'] != perm2['read'] or
                perm1['write'] != perm2['write']):
            return False
        return True

    def _manage_permissions(self):
        # Get all the existing permissions for the user
        existing_permissions = self.list_user_permissions()
        _permissions = []
        permission_delete = False
        if self.permissions:
            _permissions = self.permissions
            permission_delete = True
        elif self.vhost is not None:
            _permissions = [dict(
                vhost=self.vhost,
                configure=self.configure_priv,
                read=self.read_priv,
                write=self.write_priv,
            )]
        if not _permissions:
            return

        desired_vhosts = [_p['vhost'] for _p in _permissions]
        existing_vhosts = [_p['vhost'] for _p in existing_permissions]
        if not self.check_mode:
            # delete all the permissions that are not in the required
            for existing_perm in existing_permissions:
                if existing_perm['vhost'] not in desired_vhosts:
                    self.delete_permission(existing_perm)
                    self.changed = True

        # check if the permission exists and hasn't changed.
        for desired_perm in _permissions:
            add_vhost = False
            desired_perm = dict(
                vhost=desired_perm['vhost'],
                configure=desired_perm.get('configure_priv', '.*'),
                read=desired_perm.get('read_priv', '.*'),
                write=desired_perm.get('write_priv', '.*'),
            )
            if desired_perm['vhost'] not in existing_vhosts:
                add_vhost = True
            else:
                # The vhost is in the list. It will return one element
                existing_perm = [
                    _p for _p in existing_permissions
                    if _p['vhost'] == desired_perm['vhost']
                ][0]
                if not self._match_permission(desired_perm,
                                              existing_perm):
                    add_vhost = True

            if add_vhost:
                self.changed = True
                if not self.check_mode:
                    self.add_permission(desired_perm)
        if not self.changed:
            self.ok = True

    def exec_module(self, **params):
        for key in self.arguments_spec.keys():
            setattr(self, key, self.module.params[key])

        self._verify_permissions()
        users = self.list_users()
        user = list(filter(lambda x: x['name'] == self.name, users))

        if self.state == 'present':
            user_changed = False
            if user:
                user = user[0]
                existing_tags = user['tags']
                new_tags = self.tags.lower().strip().replace(' ', '').split(',')
                if set(existing_tags) != set(new_tags):
                    user_changed = True

                if self._check_password_changed(user['password_hash']):
                    user_changed = True
            else:
                user_changed = True

            if user_changed:
                self.add_user()
                self.changed = True

            self._manage_permissions()
        elif self.state == 'absent':
            if user:
                self.delete_user()
                self.changed = True
            else:
                self.ok = True
        if self.check_mode:
            self.result['name'] = self.name


def main():
    RabbitMQUser()


if __name__ == '__main__':
    main()
