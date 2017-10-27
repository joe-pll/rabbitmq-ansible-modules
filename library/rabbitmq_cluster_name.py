#!/usr/bin/python

# (c) 2017, Giuseppe Pellegrino <mr.giuseppepellegrino@gmail.com>

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: rabbitmq_cluster_name
short_description: Ensure RabbitMQ cluster name is set
description:
  - Ensure RabbitMQ cluster name is equal to the name passed
requirements: [ "requests >= 1.0.0" ]
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
    required: false
  name:
    description:
      - The name of the cluster
    required: true
    default: null
  ssl_enabled:
    description:
      - Whether or not RabbitMQ is listening on HTTPS
    default: false
    required: false
  ssl_verify:
    description:
      - Whether or not there must be a SSL certificate verification
'''

EXAMPLES = '''
# Ensure that the cluster name is 'testcluster'
- rabbitmq_cluster_name:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: testcluster
'''

import urllib
from ansible.module_utils.rabbitmq_common import RabbitMQ


class RabbitMQClusterName(RabbitMQ):

    def __init__(self):
        self.arguments_spec = dict(
            name=dict(type='str', required=True),
        )
        super(RabbitMQClusterName, self).__init__(
                                        derived_args_spec=self.arguments_spec,
                                        supports_check_mode=True)

    def get_cluster_name(self):
        request = self.rabbitmq_request('get', path='/api/cluster-name')
        self.error_handling(request.status_code)
        return request.json()

    def set_cluster_name(self):
        cluster_name = dict(name=self.name)
        request = self.rabbitmq_request('get',
                                        path='/api/cluster-name',
                                        payload=cluster_name)
        self.error_handling(request.status_code)

    def exec_module(self, **params):
        for key in self.arguments_spec.keys():
            setattr(self, key, self.module.params[key])

        current_cluster_name = self.get_cluster_name()
        if current_cluster_name['name'] == self.name:
            self.ok = True
        else:
            self.changed = True
            if not self.check_mode:
                self.set_cluster_name()


def main():
    """Call the RabbitMQQueue module."""
    RabbitMQQueue()


if __name__ == "__main__":
    main()
