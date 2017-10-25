#!/usr/bin/python

# (c) 2017, Giuseppe Pellegrino <mr.giuseppepellegrino@gmail.com>

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: rabbitmq_queue
short_description: Manage RabbitMQ vhost
description:
  - Create, delete, update a RabbitMQ virtual host.
requirements: [ "requests >= 1.0.0" ]
author: '"Giuseppe Pellegrino @joe-pll"'
options:
  arguments:
    description:
      - Extra arguments for the queue.
      - This argument is a key/value dictionary
  auto_delete:
    description:
      - If yes, the queue will delete itself after at least one consumer has connected, and then all consumers have disconnected.
    required: false
    choices: [yes, no]
    default: no
  auto_expires:
    description:
      - How long a queue can be unused for before it is automatically deleted (milliseconds).
    required: false
  dead_letter_exchange:
    description:
      - Optional name of an exchange to which messages will be republished if they are rejected or expire.
    required: false
  dead_letter_routing_key:
    description:
      - Optional replacement routing key to use when a message is dead-lettered. If this is not set, the message's original routing key will be used.
    required: false
  durable:
    description:
      - Durable queues are persisted to disk and thus survive broker restarts.
    required: false
    default: yes
    choices: [yes, no]
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
  max_length:
    description:
      - How many (ready) messages a queue can contain before it starts to drop them from its head.
    required: false
  max_length_bytes:
    description:
      - Total body size for ready messages a queue can contain before it starts to drop them from its head.
    required: false
  maximum_priority:
    description:
      - Maximum number of priority levels for the queue to support; if not set, the queue will not support message priorities.
    required: false
  message_ttl:
    description:
      - How long a message published to a queue can live before it is discarded (milliseconds).
    required: false
  name:
    description:
      - The name of the queue to create or update
    required: true
    default: null
    aliases: [queue]
  queue_mode:
    description:
      - The mode of the queue under which it can operate
     default: default
     choices: [default, lazy]
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
'''

EXAMPLES = '''
# Ensure that the queue 'test' exists.
- rabbitmq_queue:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: test
    state: present
    vhost: /vhost
    message_ttl: 50000

# Ensure that the user another_user has all the permissions
- rabbitmq_queue:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: test
    state: present
    vhost: /vhost
    maximum_priority: 2
    arguments:
      x-message-ttl: 50000

# Ensure that the queue 'test' is not present
- rabbitmq_queue:
    login_host: rabbitmq.example.com
    login_user: myuser
    login_password: mypassword
    name: test
    vhost: '/vhost'
    state: absent
'''

import urllib
from ansible.module_utils.rabbitmq_common import RabbitMQ


ARGUMENTS_TRANSLATOR = {
    "auto_expires": "x-expires",
    "dead_letter_exchange": "x-dead-letter-exchange",
    "dead_letter_routing_key": "x-dead-letter-routing-key",
    "max_length": "x-max-length",
    "max_length_bytes": "x-max-length-bytes",
    "maximum_priority": "x-max-priority",
    "message_ttl": "x-message-ttl",
    "queue_mode": "x-queue-mode",
}


class RabbitMQQueue(RabbitMQ):

    def __init__(self):
        self.arguments_spec = dict(
            arguments=dict(type='dict', default=dict(), required=False),
            auto_delete=dict(type='bool', default=False, required=False),
            auto_expires=dict(type='int', default=None, required=False),
            dead_letter_exchange=dict(type='str', default=None, required=False),
            dead_letter_routing_key=dict(type='str', default=None, required=False),
            durable=dict(type='bool', default=True, required=False),
            max_length=dict(type='int', default=None, required=False),
            max_length_bytes=dict(type='int', default=None, required=False),
            maximum_priority=dict(type='int', default=None, required=False),
            message_ttl=dict(type='int', default=None, required=False),
            name=dict(type='str', required=True, aliases=['queue']),
            queue_mode=dict(type='str', default='default', choices=['default', 'lazy']),
            vhost=dict(type='str', default='/', required=False),
            state=dict(type='str', default='present', choices=['present', 'absent']),
        )
        super(RabbitMQQueue, self).__init__(
                                        derived_args_spec=self.arguments_spec,
                                        supports_check_mode=True)

    def _build_path(self):
        safe_vhost = urllib.quote(self.vhost, '')
        path = '/api/queues/{vhost}'.format(vhost=safe_vhost)
        return path

    def _list(self, path):
        request = self.rabbitmq_request('get', path=path)
        self.error_handling(request.status_code)
        return request.json()

    def list_queues(self):
        return self._list(self._build_path())

    def list_vhosts(self):
        return self._list('/api/vhosts')

    def add_queue(self):
        path = '/api/queues/{vhost}/{queue}'.format(
                                    vhost=urllib.quote(self.vhost, ''),
                                    queue=urllib.quote(self.name, ''))
        queue = dict(
            durable=self.durable,
            auto_delete=self.auto_delete,
            arguments=self.arguments,
        )
        request = self.rabbitmq_request('put', path=path, payload=queue)
        self.error_handling(request.status_code)

    def delete_queue(self):
        path = '/api/queues/{vhost}/{queue}'.format(
                                    vhost=urllib.quote(self.vhost, ''),
                                    queue=urllib.quote(self.name, ''))
        request = self.rabbitmq_request('delete', path=path)
        self.error_handling(request.status_code)

    def exec_module(self, **params):
        for key in self.arguments_spec.keys():
            setattr(self, key, self.module.params[key])

        existing_vhosts_names = [v['name'] for v in self.list_vhosts()]
        if self.vhost not in existing_vhosts_names:
            self.fail('Vhost `{vhost}` does not exist '
                      'in Rabbitmq.'.format(vhost=self.vhost))

        existing_queues = self.list_queues()
        existing_queues = {q['name']: q for q in existing_queues}

        if self.state == 'present':
            for arg_key, arg_value in ARGUMENTS_TRANSLATOR.items():
                if getattr(self, arg_key) is not None:
                    self.arguments[arg_value] = getattr(self, arg_key)

            if self.name not in existing_queues.keys():
                self.changed = True
                if not self.check_mode:
                    self.add_queue()
            else:
                opts_changed = False
                existing_queue = existing_queues[self.name]
                for arg_k, arg_v in self.arguments.items():
                    if (arg_k not in existing_queue['arguments'] or
                            arg_v != existing_queue['arguments'][arg_k]):
                        opts_changed = True
                        break
                if (existing_queue['durable'] != self.durable or
                        existing_queue['auto_delete'] != self.auto_delete):
                    opts_changed = True
                if opts_changed:
                    self.fail('A queue in RabbitMQ can not be updated. '
                              'Delete the queue and re-create a new one.')
                self.ok = True
        else:
            if self.name in existing_queues.keys():
                self.changed = True
                if not self.check_mode:
                    self.delete_queue()
            else:
                self.ok = True


def main():
    """Call the RabbitMQQueue module."""
    RabbitMQQueue()


if __name__ == "__main__":
    main()
