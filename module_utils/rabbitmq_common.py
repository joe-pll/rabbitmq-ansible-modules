from ansible.module_utils.basic import AnsibleModule
import json
import requests
from requests.auth import HTTPBasicAuth
import urllib3


RABBITMQ_COMMON_ARGS = dict(
    login_host=dict(type='str', required=False, default='localhost'),
    login_port=dict(type='int', required=False, default=15672),
    login_user=dict(type='str', required=False, default='guest'),
    login_password=dict(type='str', required=False, default='guest', no_log=True),
    ssl_enabled=dict(type='bool', required=False, default=False),
    ssl_verify=dict(type='bool', required=False, default=True),
)


class RabbitMQ(object):

    def __init__(self, derived_args_spec, bypass_checks=False, no_log=False,
                 check_invalid_arguments=True, mutually_exclusive=None,
                 required_together=None, required_one_of=None,
                 add_file_common_args=False, supports_check_mode=False,
                 required_if=None):

        self.ok = False
        self.changed = False
        self.result = dict(changed=False)

        # Update the arguments
        merged_arguments_spec = RABBITMQ_COMMON_ARGS.copy()
        merged_arguments_spec.update(derived_args_spec)

        self.module = AnsibleModule(argument_spec=merged_arguments_spec,
                                    bypass_checks=bypass_checks,
                                    no_log=no_log,
                                    check_invalid_arguments=check_invalid_arguments,
                                    mutually_exclusive=mutually_exclusive,
                                    required_together=required_together,
                                    required_one_of=required_one_of,
                                    add_file_common_args=add_file_common_args,
                                    supports_check_mode=supports_check_mode,
                                    required_if=required_if)

        self.check_mode = self.module.check_mode

        for key in RABBITMQ_COMMON_ARGS.keys():
            setattr(self, key, self.module.params[key])

        self.exec_module(**self.module.params)

        if self.ok:
            self.result['ok'] = self.ok
        self.result['changed'] = self.changed
        self.exit_json()

    def error_handling(self, code):
        if code >= 300:
            self.fail("Invalid response from RabbitMQ API. Status "
                      "code {}".format(code))

    def rabbitmq_request(self, method, path='', headers={},
                         params={}, payload={}):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        rabbitmq_auth = HTTPBasicAuth(self.login_user, self.login_password)
        scheme = 'https' if self.ssl_enabled else 'http'
        url = "{scheme}://{host}:{port}{path}".format(scheme=scheme,
                                                      host=self.login_host,
                                                      port=self.login_port,
                                                      path=path)
        try:
            request = getattr(requests, method)(url,
                                                auth=rabbitmq_auth,
                                                headers=headers,
                                                params=params,
                                                data=json.dumps(payload),
                                                verify=self.ssl_verify)
            if request.status_code == 401:
                self.fail("HTTP Unauthorized error.")

            return request
        except Exception as e:
            if isinstance(e, AttributeError):
                self.fail("HTTP method `{}` not implemented".format(method))
            self.fail(str(e.message))

    def exec_module(self, **params):
        """Override the method."""
        self.fail(('Method exec_module not '
                   'implement in {}').format(self.__class__.__name__))

    def exit_json(self):
        """Wrap Ansible exit_json call.
        """
        self.module.exit_json(**self.result)

    def fail(self, message, **kwargs):
        """Wrap Ansible fail json call.

        :param message: Error message
        :type message: string
        :param kwargs: Key=value pairs
        :return: None
        """
        self.module.fail_json(msg=message, **kwargs)
