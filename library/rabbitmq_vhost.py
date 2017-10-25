#!/usr/bin/python

# (c) 2017, Giuseppe Pellegrino <mr.giuseppepellegrino@gmail.com>

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: rabbitmq_vhost
short_description: Manage RabbitMQ vhost
description:
  - Create, delete, update a RabbitMQ virtual host.
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
      - The name of the virtual host
    required: true
    default: null
    aliases: [vhost]
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
      - The state of vhost
    default: present
    choices: [present, absent]
  tracing:
    description:
      - Enable/disable tracing for a virtual host
    default: false
    required: false
'''

EXAMPLES = '''
# Ensure that the vhost /vhost exists and has tracing enabled.
- rabbitmq_vhost:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: /vhost
    state: present
    tracing: true

# Ensure that the vhost /test is not in RabbitMQ
- rabbitmq_vhost:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: /test
    state: absent
'''

import urllib
from ansible.module_utils.rabbitmq_common import RabbitMQ


class RabbitMQVhost(RabbitMQ):

    def __init__(self):
        self.arguments_spec = dict(
            name=dict(type='str', required=True, aliases=['vhost']),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            tracing=dict(type='bool', default=False, required=False),
        )
        super(RabbitMQVhost, self).__init__(
                                        derived_args_spec=self.arguments_spec,
                                        supports_check_mode=True)

    def _build_path(self):
        safe_vhost = urllib.quote(self.name, '')
        path = '/api/vhosts/{vhost}'.format(vhost=safe_vhost)
        return path

    def list_vhosts(self):
        request = self.rabbitmq_request('get', path='/api/vhosts')
        self.error_handling(request.status_code)
        return request.json()

    def add_vhost(self):
        payload = dict(tracing=self.tracing)
        request = self.rabbitmq_request('put', path=self._build_path(),
                                        payload=payload)
        self.error_handling(request.status_code)

    def delete_vhost(self):
        request = self.rabbitmq_request('delete', path=self._build_path())
        self._error_handling(request.status_code)

    def exec_module(self, **params):
        for key in self.arguments_spec.keys():
            setattr(self, key, self.module.params[key])

        vhosts = self.list_vhosts()
        vhost = list(filter(lambda x: x['name'] == self.name, vhosts))

        if self.state == 'present':
            if vhost and vhost[0]['tracing'] == self.tracing:
                self.ok = True
            else:
                self.changed = True
                if not self.check_mode:
                    self.add_vhost()
        elif self.state == 'absent':
            # if the result of the filter is not empty then the vhost exists
            if vhost:
                self.changed = True
                if not self.check_mode:
                    self.delete_vhost()
            else:
                self.ok = True
        if self.check_mode:
            self.result['vhost'] = self.name
            self.exit_json()


def main():
    """Call the RabbitMQVhost module."""
    RabbitMQVhost()


if __name__ == "__main__":
    main()
