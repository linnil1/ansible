#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Ansible by Red Hat, inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}

DOCUMENTATION = """
---
module: junos_firewall
version_added: "2.7"
author: "linnil1"
short_description: Set Firewall on Juniper JUNOS network devices
description:
  - This module can set up Firewall filter
    on Juniper JUNOS network devices.
options:
  name:
    description:
      - Name of filter.
    type: dict
    required: true
  terms:
    description:
      - List of term inside firewall.
    type: list
    suboptions:
      name:
        description:
          - Name of term.
          - Not necessary to provide. It will automatically generate
          - the name with C(term_ + Index of this term).
      from:
        description:
          - Conditions of this term.
        aliases:
          - if
      then:
        description:
          - Action of this term.
  family:
    description:
      - Protocol family of Firewall.
    default: inet
    choices: ['inet', 'inet6', 'ethernet-switching']
  aggregate:
    description: List of Firewall definitions.
  state:
    description:
      - State of the Firewall configuration.
    default: present
    choices: ['present', 'absent']
  active:
    description:
      - Specifies whether or not the configuration is active or deactivated
    default: True
    type: bool
requirements:
  - jxmlease
  - ncclient (>=v0.5.2)
notes:
  - This module requires the netconf system service be enabled on
    the remote device being managed.
  - Tested against Juniper EX4300 14.1X53-D42.3
  - Recommended connection is C(netconf). See L(the Junos OS Platform Options,../network/user_guide/platform_junos.html).
  - This module also works with C(local) connections for legacy playbooks.
extends_documentation_fragment: junos
"""

EXAMPLES = """
    - name: set Firewall
      junos_firewall:
        name: filter_test-1
        terms:
          - from:
              source-address: 192.168.1.0/24
              destination-address: 192.168.1.0/24
            then:
              count: count_name_1
              accept:
          - from:
              source-address:
                - 192.168.1.3/32
                - 192.168.2.4/32
              destination-address: 192.168.2.4/32
            then:
              log:
            name: term_name
          - then:
              discard:
        active: True
        state: present

    - name: set Firewall by aggregation
      junos_firewall:
        aggregate:
          - name: filter_test_1
            terms:
              - then:
                  discard:
            active: True
            state: present
          - name: filter_test_2
            terms:
              - then:
                  discard:
            active: True
            state: present

    - name: set ethernet-switching Firewall
      junos_firewall:
        name: filter_ethernet_switching
        family: ethernet-switching
        terms:
          - then:
              accept:
        active: True
        state: present

    - name: set routing instance
      junos_firewall:
        name: filter_test_routing_instance
        terms:
          - then:
              routing-instance:
                routing-instance-name: routing_instance_name
        active: True
        state: present
"""

RETURN = """
diff.prepared:
  description: Configuration difference before and after applying change.
  returned: when configuration is changed and diff option is enabled.
  type: string
  sample: >
         [edit firewall family inet]
         +     filter filter_test_1 {
         +         term term_0 {
         +             then {
         +                 discard;
         +             }
         +         }
         +     }
         +     filter filter_test_2 {
         +         term term_0 {
         +             then {
         +                 discard;
         +             }
         +         }
         +     }
"""

import collections

from copy import deepcopy

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.common.utils import remove_default_spec
from ansible.module_utils.network.junos.junos import junos_argument_spec, tostring
from ansible.module_utils.network.junos.junos import load_config, map_params_to_obj, map_obj_to_ele, to_param_list
from ansible.module_utils.network.junos.junos import commit_configuration, discard_changes, locked_config

try:
    from lxml.etree import fromstring
except ImportError:
    from xml.etree.ElementTree import fromstring

try:
    import jxmlease
    HAS_JXMLEASE = True
except ImportError:
    HAS_JXMLEASE = False

USE_PERSISTENT_CONNECTION = True


def set_term_ele(ele, term):
    if not term:
        return ele
    filter_ele = ele.xpath('//filter')[0]
    for i, term in enumerate(term):
        if not term.get('name'):
            term['name'] = 'term_' + str(i)

        xml_string = jxmlease.XMLDictNode({'term': term}).emit_xml()
        xml_tree = fromstring(xml_string.encode())
        xml_tree.insert(0, xml_tree.find('name'))
        filter_ele.append(xml_tree)

    return ele


def main():
    """ main entry point for module execution
    """
    element_spec = dict(
        name=dict(),
        terms=dict(type='list', elements='dict', options=dict([
            ('name', dict()),
            ('from', dict(type='dict', aliases=['if'])),
            ('then', dict(type='dict')),
        ])),
        state=dict(default='present', choices=['present', 'absent']),
        family=dict(default='inet',
                    choices=['inet', 'inet6', 'ethernet-switching']),
        active=dict(default=True, type='bool')
    )

    aggregate_spec = deepcopy(element_spec)
    aggregate_spec['name'] = dict(required=True)

    # remove default in aggregate spec, to handle common arguments
    remove_default_spec(aggregate_spec)

    argument_spec = dict(
        aggregate=dict(type='list', elements='dict', options=aggregate_spec)
    )

    argument_spec.update(element_spec)
    argument_spec.update(junos_argument_spec)

    required_one_of = [['aggregate', 'name']]
    mutually_exclusive = [['aggregate', 'name']]

    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=required_one_of,
                           mutually_exclusive=mutually_exclusive,
                           supports_check_mode=True)

    warnings = list()
    result = {'changed': False}

    if warnings:
        result['warnings'] = warnings

    top_format = 'firewall/family/{}/filter'

    param_to_xpath_map = collections.OrderedDict()
    param_to_xpath_map.update([
        ('name', {'xpath': 'name', 'is_key': True}),
    ])
    params = to_param_list(module)

    requests = list()
    for param in params:
        # if key doesn't exist in the item, get it from module.params
        for key in param:
            if param.get(key) is None:
                param[key] = module.params[key]
        top = top_format.format(param['family'])

        item = param.copy()
        want = map_params_to_obj(module, param_to_xpath_map, param=item)
        ele = map_obj_to_ele(module, want, top, param=item)
        requests.append(set_term_ele(ele, param['terms']))

    diff = None
    with locked_config(module):
        for req in requests:
            diff = load_config(module, tostring(req), warnings, action='replace')

        commit = not module.check_mode
        if diff:
            if commit:
                commit_configuration(module)
            else:
                discard_changes(module)
            result['changed'] = True

            if module._diff:
                result['diff'] = {'prepared': diff}

    module.exit_json(**result)


if __name__ == "__main__":
    main()
