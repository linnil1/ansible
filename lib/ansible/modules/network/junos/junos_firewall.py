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
author: "linnil1 (https://github.com/linnil1)"
short_description: Manage Firewall on Juniper JUNOS network devices
description:
  - This module can setting up Firewall logic
    on Juniper JUNOS network devices.
options:
  name:
    description:
      - Name of the filter
    required: true
  terms:
    description:
      - each term block
    required: true
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
  - ncclient (>=v0.5.2)
notes:
  - This module requires the netconf system service be enabled on
    the remote device being managed.
  - Tested against Juniper EX4300
  - Recommended connection is C(netconf). See L(the Junos OS Platform Options,../network/user_guide/platform_junos.html).
  - This module also works with C(local) connections for legacy playbooks.
extends_documentation_fragment: junos
"""

EXAMPLES = """
    - name: set Firewall
      junos_firewall:
        name: f5
        terms:
          - from:
              source-address: 192.168.200.3/32
              destination-address: 192.168.201.10/32
            then: 
              count: c1
              accept:
          - from:
              source-address: 
                - 192.168.201.3/32
                - 192.168.201.4/32
              destination-address: 192.168.200.10/32
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
          - name: f5
            terms:
              - then:
                  discard:
            active: True
            state: present
          - name: f6
            terms:
              - then:
                  discard:
            active: True
            state: present
"""

RETURN = """
diff.prepared:
  description: Configuration difference before and after applying change.
  returned: when configuration is changed and diff option is enabled.
  type: string
  sample: >
"""

import collections

from copy import deepcopy

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.common.utils import remove_default_spec
from ansible.module_utils.network.junos.junos import junos_argument_spec, tostring
from ansible.module_utils.network.junos.junos import load_config, map_params_to_obj, map_obj_to_ele, to_param_list
from ansible.module_utils.network.junos.junos import commit_configuration, discard_changes, locked_config

try:
    from lxml.etree import Element, SubElement, fromstring, tostring
    HAS_LXML = True
except ImportError:
    from xml.etree.ElementTree import Element, SubElement, fromstring, tostring
    HAS_LXML = False

USE_PERSISTENT_CONNECTION = True

def set_term_ele(ele, term):
    terms_ele = []
    for i, term in enumerate(term):
        term_ele = Element('term')
        if term.get('name'):
            SubElement(term_ele, 'name').text = term['name']
        else:
            SubElement(term_ele, 'name').text = 't' + str(i)

        terms_parm = ['from', 'then']
        for ft in terms_parm:
            if term.get(ft) :
                ft_ele = SubElement(term_ele, ft)
                for key, value in term[ft].items():
                    if not isinstance(value, (list, tuple)):
                        value = [value]
                    for val in value:
                        SubElement(ft_ele, key).text = val

        terms_ele.append(term_ele)

    filter_ele = ele.xpath('//filter')[0]
    for term_ele in terms_ele:
        filter_ele.append(term_ele)
    return ele

def main():
    """ main entry point for module execution
    """
    element_spec = dict(
        name=dict(),
        interfaces=dict(),
        terms=dict(type='list'),
        state=dict(default='present', choices=['present', 'absent']),
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

    top = 'firewall/family/inet/filter'

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
