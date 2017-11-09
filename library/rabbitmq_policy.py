#!/usr/bin/python

# (c) 2017, Giuseppe Pellegrino <mr.giuseppepellegrino@gmail.com>

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: rabbitmq_policy
short_description: Manage RabbitMQ policy
description:
  - Create, delete, update a RabbitMQ policy.
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
      - The name of the policy
    required: true
    default: null
    aliases: [policy]
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
      - The state of policy
    default: present
    choices: [present, absent]
  apply_to:
    description:
      - To which kind the policy must be applied
    default: all
    choices: [all, queues, exchanges]
  pattern:
    description:
      - The regex patter for chosing the queues/exchanges where to apply the policy
    required: true
  definition:
    description:
      - A dictionary of key/value that will be injected into the map of optional arguments of the matching queues and exchanges.
    required: false
  priority:
    description:
      - Define the priority when more than one policy can match a given exchange or queue.
      - The policy with the greatest priority will apply.
    required: false
    default: 0
  vhost:
    description:
      - The vhost where the policy should be applied
    default: /
    required: false
'''

EXAMPLES = '''
# Ensure that the user 'another_user' exists and the vhost has the permissions
- rabbitmq_policy:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: mypolicy
    state: present
    vhost: /test
    pattern: "^amq\."
    apply_to: queues

# Apply federation definition on all the exchanges of the vhost /test that
# satisfy the pattern
- rabbitmq_policy:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: mypolicy
    state: present
    vhost: /test
    pattern: "^amq\."
    definition:
      "federation-upstream-set": "all"
    apply_to: exchanges

# Ensure the policy does not exist on the vhost /
- rabbitmq_policy:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: mypolicy
    state: absent
'''

import urllib
from ansible.module_utils.rabbitmq_common import RabbitMQ


class RabbitMQPolicy(RabbitMQ):

    def __init__(self):
        self.arguments_spec = dict(
            name=dict(type='str', required=True, aliases=['policy']),
            apply_to=dict(type='str', default='all', choices=['all', 'exchanges', 'queues']),
            definition=dict(type='dict', default=dict(), required=False),
            pattern=dict(type='str', default='.*', required=True),
            priority=dict(type='int', default=0, required=False),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            vhost=dict(type='str', default='/', required=False),
        )
        super(RabbitMQPolicy, self).__init__(
                                    derived_args_spec=self.arguments_spec,
                                    supports_check_mode=True)

    def _list(self, path):
        request = self.rabbitmq_request('get', path=path)
        self.error_handling(request.status_code)
        return request.json()

    def list_policies(self):
        safe_vhost = urllib.quote(self.vhost, '')
        path = '/api/policies/{vhost}'.format(vhost=safe_vhost)
        return self._list(path)

    def add_policy(self):
        safe_vhost = urllib.quote(self.vhost, '')
        safe_policy = urllib.quote(self.name, '')
        path = '/api/policies/{vhost}/{policy}'.format(vhost=safe_vhost,
                                                       policy=safe_policy)
        policy = {
            "pattern": self.pattern,
            "definition": self.definition,
            "priority": self.priority,
            "apply-to": self.apply_to,
        }
        request = self.rabbitmq_request('put', path=path, payload=policy)
        self.error_handling(request.status_code)

    def delete_policy(self):
        safe_vhost = urllib.quote(self.vhost, '')
        safe_policy = urllib.quote(self.name, '')
        path = '/api/policies/{vhost}/{policy}'.format(vhost=safe_vhost,
                                                       policy=safe_policy)
        request = self.rabbitmq_request('delete', path=path)
        self.error_handling(request.status_code)

    def exec_module(self, **params):
        for key in self.arguments_spec.keys():
            setattr(self, key, self.module.params[key])

        if not isinstance(self.definition, dict):
            self.fail('Definition key must be a dictionary!')

        existent_policies = self.list_policies()
        existent_policy_names = [p['name'] for p in existent_policies]

        if self.state == 'present':
            if self.name in existent_policy_names:
                policy = list(filter(lambda x: x['name'] == self.name, existent_policies))[0]

                if (self.pattern != policy['pattern'] or
                        self.apply_to != policy['apply-to'] or
                        self.priority != policy['priority'] or
                        self.definition != policy['definition']):
                    self.changed = True

                if not self.changed:
                    self.ok = True
            else:
                self.changed = True

            if self.changed:
                if not self.check_mode:
                    self.add_policy()
        else:
            if self.name not in existent_policy_names:
                self.ok = True
            else:
                if not self.check_mode:
                    self.delete_policy()
                self.changed = True


def main():
    RabbitMQPolicy()


if __name__ == '__main__':
    main()
