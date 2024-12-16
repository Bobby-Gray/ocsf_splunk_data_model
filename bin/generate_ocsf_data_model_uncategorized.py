import json
import os
import pprint
import re
import requests
import traceback

#
# Script to convert OCSF schema to a valid splunk data model titled, 'secops_ocsf_dm.json'.
#
# Assumes local ocsf-server is running via localhost:8080
#
# Once created, json schema validation can be performed via secops_dm_json_validation.py script and splunk_data_model_schema.json before uploading to Splunk.
#   Ex: python3 ./secops_splunk_ocsf_dm_json_validation.py ./splunk_data_model_schema.json secops_ocsf_dm.json
#

api_url = 'http://localhost:8080'

def extend_dictionary_keys(base_fieldName, dictionary, class_owner):
    # print(f'Gathering objects for {base_fieldName}')
    base = base_fieldName
    obj_owner = class_owner
    if isinstance(dictionary, dict):
        for key, value in dictionary.items():
            if 'object_type' in key:
                # If field_type is 'object_t', make API request to retrieve next layer
                next_layer = make_api_request(value)  # You need to implement make_api_request function
                if next_layer:
                    for next_layer_iter in range(len(next_layer)):
                        for class_field, field_obj in next_layer[next_layer_iter].items():
                            obj_source = field_obj.get('_source')
                            field_type = field_obj.get('type')
                            obj_fieldname = (f'{base_fieldName}.{class_field}')
                            comment = field_obj.get('description')
                            if field_obj.get('requirement') == 'required':
                                required = True
                            else:
                                required = False
                            multivalue = False
                            hidden = False
                            editable = True
                            object_type = field_obj.get('object_type') or "not_found"
                            level = obj_fieldname.count('.')
                            if field_type == 'object_t' and level <= 1:
                                    # First level object + nested object
                                    # e.g.,src_endpoint.os
                                    # print('test1')
                                    # print(obj_fieldname)
                                    fields.append({"fieldName": obj_fieldname, "owner": "secops_dm", "type": field_type, "fieldSearch": "", "required": required, "multivalue": multivalue, "hidden": hidden, "editable": editable, "displayName": obj_fieldname, "comment": json.dumps(comment)})
                                    dictionary[key] = extend_dictionary_keys(obj_fieldname, next_layer, class_owner)
                                    base_fieldName = obj_fieldname
                                    sub_layer = make_api_request(class_field)
                                    if sub_layer:
                                        for sub_layer_iter in range(len(sub_layer)):
                                            for class_field, field_obj in sub_layer[sub_layer_iter].items():
                                                # First level object + nested object + field
                                                # e.g., src_endpoint.os.name
                                                field_type = field_obj.get('type')
                                                obj_fieldname = (f'{base_fieldName}.{class_field}')
                                                comment = field_obj.get('description')
                                                if field_obj.get('requirement') == 'required':
                                                    required = True
                                                else:
                                                    required = False
                                                multivalue = False
                                                hidden = False
                                                editable = True
                                                object_type = field_obj.get('object_type') or "not_found"
                                                level = obj_fieldname.count('.')
                                                # print('test1.2')
                                                fields.append({"fieldName": obj_fieldname, "owner": "secops_dm", "type": field_type, "fieldSearch": "", "required": required, "multivalue": multivalue, "hidden": hidden, "editable": editable, "displayName": obj_fieldname, "comment": json.dumps(comment)})
                                                if sub_layer_iter == (len(sub_layer) - 1):
                                                    # print('1.2.1')
                                                    # print(obj_fieldname)
                                                    dictionary[key] = extend_dictionary_keys(base, next_layer, class_owner)
                                                else:
                                                    # print('1.2.2')
                                                    # print(obj_fieldname)
                                                    dictionary[key] = extend_dictionary_keys(base, sub_layer, class_owner)
                            if field_type == 'object_t' and level > 1:
                                    # print('test2')
                                    obj_fieldname = (f'{base}.{class_field}')
                                    # print(obj_fieldname)
                                    fields.append({"fieldName": obj_fieldname, "owner": "secops_dm", "type": field_type, "fieldSearch": "", "required": required, "multivalue": multivalue, "hidden": hidden, "editable": editable, "displayName": obj_fieldname, "comment": json.dumps(comment)})
                                    dictionary[key] = extend_dictionary_keys(obj_fieldname, next_layer, class_owner)
                                    base_fieldName = obj_fieldname
                                    sub_layer = make_api_request(object_type)
                                    if sub_layer:
                                        for sub_layer_iter in range(len(sub_layer)):
                                            for class_field, field_obj in sub_layer[sub_layer_iter].items():
                                                field_type = field_obj.get('type')
                                                if field_type == 'object_t':
                                                    # print(field_type)
                                                    obj_fieldname = (f'{base_fieldName}.{class_field}')
                                                    comment = field_obj.get('description')
                                                    if field_obj.get('requirement') == 'required':
                                                        required = True
                                                    else:
                                                        required = False
                                                    multivalue = False
                                                    hidden = False
                                                    editable = True
                                                    object_type = field_obj.get('object_type') or "not_found"
                                                    # print('test2.1')
                                                    # print(obj_fieldname)
                                                    sub_sub_layer = make_api_request(object_type) 
                                                    if sub_sub_layer:
                                                        for sub_sub_layer_iter in range(len(sub_sub_layer)):
                                                            for class_field, field_obj in sub_sub_layer[sub_sub_layer_iter].items():
                                                                field_type = field_obj.get('type')
                                                                sub_obj_fieldname = (f'{obj_fieldname}.{class_field}')
                                                                comment = field_obj.get('description')
                                                                if field_obj.get('requirement') == 'required':
                                                                    required = True
                                                                else:
                                                                    required = False
                                                                multivalue = False
                                                                hidden = False
                                                                editable = True
                                                                object_type = field_obj.get('object_type') or "not_found"
                                                                level = obj_fieldname.count('.')
                                                                # print('test2.1.1')
                                                                if sub_sub_layer_iter == (len(sub_sub_layer) - 1):
                                                                    # print('test2.1.1.1')
                                                                    # print(obj_fieldname)
                                                                    fields.append({"fieldName": obj_fieldname, "owner": "secops_dm", "type": field_type, "fieldSearch": "", "required": required, "multivalue": multivalue, "hidden": hidden, "editable": editable, "displayName": obj_fieldname, "comment": json.dumps(comment)})
                                                                    dictionary[key] = extend_dictionary_keys(obj_fieldname, next_layer, class_owner)
                                                                else:
                                                                    break_inf = sub_obj_fieldname.split('.')
                                                                    if break_inf[-1] == break_inf[-2] or break_inf[-3] == break_inf[-2]:
                                                                        # print('test2.1.1.2')
                                                                        # print('-' + sub_obj_fieldname)
                                                                        pass
                                                                    elif len(break_inf) > 5:
                                                                        if (break_inf[-2] and break_inf[-3]) == (break_inf[-4] and break_inf[-5]):
                                                                            # print('test2.1.1.4')
                                                                            # print('-' + sub_obj_fieldname)
                                                                            pass
                                                                    else:
                                                                        # print('test2.1.1.3')
                                                                        # print(sub_obj_fieldname)
                                                                        fields.append({"fieldName": sub_obj_fieldname, "owner": "secops_dm", "type": field_type, "fieldSearch": "", "required": required, "multivalue": multivalue, "hidden": hidden, "editable": editable, "displayName": sub_obj_fieldname, "comment": json.dumps(comment)})
                                                                        dictionary[key] = extend_dictionary_keys(sub_obj_fieldname, field_obj, class_owner)

                         
                                                else:
                                                    obj_fieldname = (f'{base_fieldName}.{class_field}')
                                                    comment = field_obj.get('description')
                                                    if field_obj.get('requirement') == 'required':
                                                        required = True
                                                    else:
                                                        required = False
                                                    multivalue = False
                                                    hidden = False
                                                    editable = True
                                                    object_type = field_obj.get('object_type') or "not_found"
                                                    level = obj_fieldname.count('.')
                                                    # print('test2.2')
                                                    # print(obj_fieldname)
                                                    fields.append({"fieldName": obj_fieldname, "owner": "secops_dm", "type": field_type, "fieldSearch": "", "required": required, "multivalue": multivalue, "hidden": hidden, "editable": editable, "displayName": obj_fieldname, "comment": json.dumps(comment)})
                                                    dictionary[key] = extend_dictionary_keys(base, sub_layer, class_owner)
                            
                            else:
                                if '.' in str(base_fieldName):
                                    # First level object + removing nested object value from previous run & killing duplicate loop from previous run when out of scope
                                    # e.g., src_endpoint.instance_uid
                                    level_obj_source = field_obj.get('_source')
                                    res = base_fieldName.split('.')
                                    obj_fieldname = (f'{res[0]}.{class_field}')
                                    if obj_source == level_obj_source:
                                        fields.append({"fieldName": obj_fieldname, "owner": "secops_dm", "type": field_type, "fieldSearch": "", "required": required, "multivalue": multivalue, "hidden": hidden, "editable": editable, "displayName": obj_fieldname, "comment": json.dumps(comment)})
                                        dictionary[key] = extend_dictionary_keys(base, next_layer, class_owner)
                                        # print('test3')
                                        # print(obj_fieldname)
                                    else:
                                        # print('test3.1')
                                        # print(obj_fieldname)
                                        pass 
                                # First level object + field
                                # e.g., src_endpoint.name
                                else:
                                    fields.append({"fieldName": obj_fieldname, "owner": "secops_dm", "type": field_type, "fieldSearch": "", "required": required, "multivalue": multivalue, "hidden": hidden, "editable": editable, "displayName": obj_fieldname, "comment": json.dumps(comment)})
                                    dictionary[key] = extend_dictionary_keys(base, next_layer, class_owner)
                                    # print('test4')
                                    # print(obj_fieldname)
            else:
                dictionary[key] = extend_dictionary_keys(base, value, class_owner)
    return dictionary

def make_api_request(data):
    try: 
        obj_response = requests.get(f'{api_url}/api/objects/{data}')
        status = obj_response.status_code
    except Exception as e:
        print(e)
    if status == 200:
        obj_mapping = obj_response.json().get('attributes')
        return obj_mapping  

def generate_mapping(api_url):
    global fields
    # Building ocsf resource variables
    categories_response = requests.get(f'{api_url}/api/categories/')
    categories_mapping = categories_response.json().get('attributes')
    classes_response = requests.get(f'{api_url}/api/classes/')
    classes_mapping = classes_response.json()
    base_objects = []
    objects = []
    objectNameList = [
        "secops_dm"
    ]
    fields = []
    base_calculations = []
    base_fields = [{
                "fieldName": "_time",
                "owner": "BaseEvent",
                "type": "string",
                "fieldSearch": "",
                "required": False,
                "multivalue": False,
                "hidden": False,
                "editable": True,
                "displayName": "_time",
                "comment": ""
            },
            {
                "fieldName": "host",
                "owner": "BaseEvent",
                "type": "string",
                "fieldSearch": "",
                "required": False,
                "multivalue": False,
                "hidden": False,
                "editable": True,
                "displayName": "host",
                "comment": ""
            },
            {
                "fieldName": "source",
                "owner": "BaseEvent",
                "type": "string",
                "fieldSearch": "",
                "required": False,
                "multivalue": False,
                "hidden": False,
                "editable": True,
                "displayName": "source",
                "comment": ""
            },
            {
                "fieldName": "sourcetype",
                "owner": "BaseEvent",
                "type": "string",
                "fieldSearch": "",
                "required": False,
                "multivalue": False,
                "hidden": False,
                "editable": True,
                "displayName": "sourcetype",
                "comment": ""
            }
            ]
    base_search = str("(`secops_dm_indexes`)")
    base_constraints = [{"search": base_search, "owner": "secops_ocsf_dm"}]
    base_objects.append({"objectName": "secops_ocsf_dm", "displayName": "secops_ocsf_dm", "parentName": 'BaseEvent', "comment": "secops data model containing all possible fields from the secops index.", "fields": base_fields, "calculations": base_calculations, "constraints": base_constraints, "lineage": "secops_ocsf_dm" })
    for cat in (categories_mapping):
        print(f'Working on category: {cat}')
        # Ex: cat: system
        parentName = categories_mapping[cat].get('name')
        # print(f'parentName: {parentName}')
        # Ex: parentName: system
        displayName = categories_mapping[cat].get('caption')
        # print(f'displayName: {displayName}')
        # Ex: displayName: System Activity
        base_comment = categories_mapping[cat].get('description')
        # print(f'displayName: {displayName}')
        # Ex: displayName: System Activity  
        classes = categories_mapping[cat].get('classes')
        # print(f'classes: {classes}')
        # Ex: classes: {'kernel_activity': {'name': 'kernel_activity', 'description': 'Kernel Activity events report when an process creates, reads, or deletes a kernel resource.', 'uid': 1003, 'extends': 'system', 'caption': 'Kernel Activity', 'profiles': ['cloud', 'datetime', 'host', 'security_control', 'container']},...
        
        for cat_class in classes:
            calculations = []
            constraints = []
            # print(f'classes[cat_class]: {classes[cat_class]}')
            # Ex: classes[cat_class]: {'name': 'kernel_activity', 'description': 'Kernel Activity events report when an process creates, reads, or deletes a kernel resource.', 'uid': 1003, 'extends': 'system', 'caption': 'Kernel Activity', 'profiles': ['cloud', 'datetime', 'host', 'security_control', 'container']}
            objectName = classes[cat_class].get('name')
            # print(f'objectName: {objectName}')
            # Ex: objectName: kernel_activity
            object_displayName = classes[cat_class].get('caption')
            # print(f'object_displayName: {object_displayName}')
            # Ex: object_displayName: Kernel Activity
            lineage = str(parentName + "." + objectName)
            # print(f'lineage: {lineage}')
            # Ex: lineage: system.kernel_activity
            owner = parentName
            # print(f'owner: {owner}')
            # Ex: owner: system
            comment = classes[cat_class].get('description')
            # print(f'comment: {comment}')
            # Ex: comment: Kernel Activity events report when an process creates, reads, or deletes a kernel resource.
            try: 
                for class_map in range(len(classes_mapping)):
                    # print(f'classes_mapping[class_map]: {classes_mapping[class_map]}')
                    # Ex: classes_mapping[class_map]: {'name': 'cpu_usage', 'description': 'CPU Usage events report service or application CPU usage statistics.', 'extension': 'dev', 'uid': 99935000, 'extends': 'diagnostic', 'category': 'dev/diagnostic', 'extension_id': 999, 'caption': 'CPU Usage', 'profiles': ['cloud', 'datetime'], 'category_name': 'Diagnostic'}
                    if objectName == classes_mapping[class_map].get('name'):
                        c_name = classes_mapping[class_map].get('name')
                        print(f'Working on class: {c_name}')
                        # Ex: c_name: cpu_usage
                        c_extension = classes_mapping[class_map].get('extension') or "not_found"
                        # print(f'c_extension: {c_extension}')
                        # Ex: c_extension: dev
                        if c_extension == 'dev':
                            class_response = requests.get(f'{api_url}/api/classes/dev/{c_name}')
                        else:
                            class_response = requests.get(f'{api_url}/api/classes/{c_name}')
                        class_mapping = class_response.json()
                        # print(f'class_mapping: {class_mapping}')
                        # Ex: class_mapping: {'attributes': [{'observables': {'type': 'object_t', 'description': 'The observables associated with the event or a finding.', 'group': 'primary', 'is_array': True, 'requirement': 'recommended', 'caption': 'Observables', 'object_name': 'Observable', 'object_type': 'observable', '_source': 'base_event'}}, {'unmapped': {'type': 'object_t', 'description': 'The attributes that are not mapped to the event schema. The names and values of those attributes are specific to the event source.', 'group': 'context', 'requirement': 'optional', 'caption': 'Unmapped Data', 'object_name': 'Object', 'object_type': 'object', '_source': 'base_event'}},...
                        class_attributes = class_mapping.get('attributes')
                        # print(f'class_attributes: {class_attributes}')
                        # Ex: class_attributes: [{'observables': {'type': 'object_t', 'description': 'The observables associated with the event or a finding.', 'group': 'primary', 'is_array': True, 'requirement': 'recommended', 'caption': 'Observables', 'object_name': 'Observable', 'object_type': 'observable', '_source': 'base_event'}}, {'unmapped': {'type': 'object_t', 'description': 'The attributes that are not mapped to the event schema. The names and values of those attributes are specific to the event source.', 'group': 'context', 'requirement': 'optional', 'caption': 'Unmapped Data', 'object_name': 'Object', 'object_type': 'object', '_source': 'base_event'}},...
                        for class_iter in range(len(class_attributes)):
                            # print(f'class_attributes[class_iter].items(): {class_attributes[class_iter].items()}')
                            # Ex: class_attributes[class_iter].items(): dict_items([('observables', {'type': 'object_t', 'description': 'The observables associated with the event or a finding.', 'group': 'primary', 'is_array': True, 'requirement': 'recommended', 'caption': 'Observables', 'object_name': 'Observable', 'object_type': 'observable', '_source': 'base_event'})])
                            for class_field, field_obj in class_attributes[class_iter].items():
                                print(f'Working on class fields and sub objects for: {class_field}')
                                # Ex: class_field: observables
                                # print(f'field_obj: {field_obj}')
                                # Ex: field_obj: {'type': 'object_t', 'description': 'The observables associated with the event or a finding.', 'group': 'primary', 'is_array': True, 'requirement': 'recommended', 'caption': 'Observables', 'object_name': 'Observable', 'object_type': 'observable', '_source': 'base_event'}
                                field_type = field_obj.get('type')
                                # print(f'field_type: {field_type}')
                                # Ex: field_type: object_t
                                fieldName = class_field
                                # print(f'fieldName: {fieldName}')
                                # Ex: fieldName: observables
                                class_owner = objectName
                                # print(f'owner: {owner}')
                                # Ex: owner: kernel_activity
                                field_displayName = class_field
                                # print(f'field_displayName: {field_displayName}')
                                # Ex: field_displayName: observables
                                comment = field_obj.get('description')
                                # print(f'comment: {comment}')
                                # comment: The observables associated with the event or a finding.
                                if field_obj.get('requirement') == 'required':
                                    required = True
                                else:
                                    required = False
                                multivalue = False
                                hidden = False
                                editable = True
                                if field_type == 'object_t':
                                    base_fieldName = fieldName
                                    # print(base_fieldName)
                                    extend_dictionary_keys(base_fieldName, field_obj, class_owner)
                                else: 
                                    fields.append({"fieldName": fieldName, "owner": "secops_dm", "type": field_type, "fieldSearch": "", "required": required, "multivalue": multivalue, "hidden": hidden, "editable": editable, "displayName": field_displayName, "comment": json.dumps(comment)})
            except Exception as e:
                print(f'print("There was an error: " + {e.args[0]} + ". The line where the code failed was " + {str(traceback.print_exc())}')
    ## Custom CloudSIEM Fields Append
    fields.append({"fieldName": "enrichments{}.data.score", "owner": "secops_dm", "type": "string", "fieldSearch": "", "required": False, "multivalue": False, "hidden": False, "editable": True, "displayName": "enrichments{}.data.score", "comment": "Custom OCSF field introduced by CloudSIEM and appended during data model construction."})
    fields.append({"fieldName": "enrichments{}.data.score_id", "owner": "secops_dm", "type": "string", "fieldSearch": "", "required": False, "multivalue": False, "hidden": False, "editable": True, "displayName": "enrichments{}.data.score_id", "comment": "Custom OCSF field introduced by CloudSIEM and appended during data model construction."})
    fields.append({"fieldName": "enrichments{}.data.tags{}", "owner": "secops_dm", "type": "string", "fieldSearch": "", "required": False, "multivalue": False, "hidden": False, "editable": True, "displayName": "enrichments{}.data.tags{}", "comment": "Custom OCSF field introduced by CloudSIEM and appended during data model construction."})
    res = []
    [res.append(x) for x in fields if x not in res]
    fields = res
    # pprint.pprint(fields)
    for f in fields:
        for fk, fv in f.items():
            if fv == "category_name":
                f.update(
                    {
                    "fieldName": "category_name",
                    "owner": "secops_dm",
                    "type": "string_t",
                    "fieldSearch": "",
                    "required": False,
                    "multivalue": False,
                    "hidden": False,
                    "editable": True,
                    "displayName": "category_name",
                    "comment": ""
                    })
                print(f)
            elif fv == "class_name":
                f.update(
                    {
                    "fieldName": "class_name",
                    "owner": "secops_dm",
                    "type": "string_t",
                    "fieldSearch": "",
                    "required": False,
                    "multivalue": False,
                    "hidden": False,
                    "editable": True,
                    "displayName": "class_name",
                    "comment": ""
                    })
                print(f)
    res = []
    [res.append(x) for x in fields if x not in res]
    fields = res
    obj_base_search = str("tag=secops_dm")
    obj_base_constraints = [{"search": obj_base_search, "owner": "secops_dm"}]
    objects.append({"objectName": "secops_dm", "displayName": "secops data model", "parentName": "secops_ocsf_dm", "comment": "secops data model containing all possible fields from the secops index.", "fields": fields, "calculations": base_calculations, "constraints": obj_base_constraints, "lineage":  "secops_ocsf_dm.secops_dm" })
    objects_dedup = []
    [objects_dedup.append(x) for x in objects if x not in objects_dedup]
    objects = objects_dedup
    for base_object in base_objects:
        objects.insert(0, base_object)
    event_based = int(len(objectNameList))
    secops = {
    "modelName": "secops_ocsf_dm",
    "displayName": "secops_ocsf_dm",
    "description": "Security Operations data model version 1.3.",
    "objectSummary": {
        "Event-Based": event_based,
        "Transaction-Based": 0,
        "Search-Based": 0
    }, 
    "objects": objects,
    "objectNameList": objectNameList
    }
    with open('secops_ocsf_dm.json', 'w') as fp:
        json.dump(secops, fp, indent=2)
    print(f'Done! secops_ocsf_dm.json file created')
    return secops

def cleanup_json():
    print(f'Data model population complete. Cleaning up type values.')
    with open(os.path.join(os.getcwd(), 'secops_ocsf_dm.json'), "r") as f:
        secops_dm = f.read()
    find_types = re.compile('"type": "\w+"')
    matchTypes = find_types.findall(secops_dm)
    str = '"type": "string"'
    num = '"type": "number"'
    ip = '"type": "ipv4"'
    boo = '"type": "boolean"'
    dev = 'dev_'
    # # test_possible_types = []
    # # [test_possible_types.append(x) for x in matchTypes if x not in test_possible_types]
    # # print(f'Possible types: {test_possible_types}')
    for match in matchTypes:
        if match == '"type": "integer_t"':
            secops_dm = re.sub(match, num, secops_dm)
            print(f'replacing {match} w/ {num}')
    find_types = re.compile('"type": "\w+"')
    matchTypes = find_types.findall(secops_dm)
    for match in matchTypes:
        if match == '"type": "float_t"':
            secops_dm = re.sub(match, num, secops_dm)
            print(f'replacing {match} w/ {num}')
    find_types = re.compile('"type": "\w+"')
    matchTypes = find_types.findall(secops_dm)
    for match in matchTypes:
        if match == '"type": "boolean_t"':
            secops_dm = re.sub(match, boo, secops_dm)
            print(f'replacing {match} w/ {boo}')
    find_types = re.compile('"type": "\w+"')
    matchTypes = find_types.findall(secops_dm)
    for match in matchTypes:
        if match == '"type": "ip_t"':
            secops_dm = re.sub(match, ip, secops_dm)
            print(f'replacing {match} w/ {ip}')
    find_types = re.compile('"type": "\w+"')
    matchTypes = find_types.findall(secops_dm)
    for match in matchTypes:
        if match != num and match != ip and match != boo:
            secops_dm = re.sub(match, str, secops_dm)
            print(f'replacing {match} w/ {str}')
    find_types = re.compile('"type": null')
    matchTypes = find_types.findall(secops_dm)
    for match in matchTypes:
        if match == '"type": null':
            secops_dm = re.sub(match, str, secops_dm)
            print(f'replacing {match} w/ {str}')
    find_types = re.compile('dev/')
    matchTypes = find_types.findall(secops_dm)
    for match in matchTypes:
        if match == 'dev/':
            secops_dm = re.sub(match, dev, secops_dm)
            print(f'replacing {match} w/ {dev}')
    curly_fields_replace = {}
    curly_fields = ['actor.authorizations{}.decision', 'actor.authorizations{}.policy.name', 'actor.authorizations{}.policy.uid', 'answers{}.class', 'answers{}.flag_ids', 'answers{}.rdata', 'answers{}.type', 'attacks{}.tactic.name', 'attacks{}.tactic.src_url', 'attacks{}.tactic.uid', 'attacks{}.technique.name', 'attacks{}.technique.src_url', 'attacks{}.technique.uid', 'attacks{}.version', 'enrichments{}.data.score', 'enrichments{}.data.score_id', 'enrichments{}.data.tags{}', 'enrichments{}.name', 'enrichments{}.provider', 'enrichments{}.type', 'enrichments{}.value', 'file.hashes{}.algorithm', 'file.hashes{}.algorithm_id', 'file.hashes{}.value', 'job.file.hashes{}.algorithm', 'job.file.hashes{}.algorithm_id', 'job.file.hashes{}.value', 'observables{}.name', 'observables{}.type', 'observables{}.type_id', 'observables{}.value']
    for c in curly_fields:
        curly_fields_replace[c] = c.replace("{}", "")
    #pprint.pprint(curly_fields_replace)
    find_curly_fieldname = re.compile('"fieldName": "[a-zA-Z_.]+"')
    find_curly_displayname = re.compile('"displayName": "[a-zA-Z_.]+"')
    match_curly_fieldname = find_curly_fieldname.findall(secops_dm)
    for cf_match in match_curly_fieldname:
        for cf_0, cf_1 in curly_fields_replace.items():
            new_cf = '"fieldName": ' + '"' + cf_0 + '"' 
            old_cf = '"fieldName": ' + '"' + cf_1 + '"' 
            if cf_match == old_cf:
                secops_dm = re.sub(cf_match, new_cf, secops_dm)
                print(f'replacing {cf_match} w/ {new_cf}')
    match_curly_displayname = find_curly_displayname.findall(secops_dm)
    for cd_match in match_curly_displayname:
        for cd_0, cd_1 in curly_fields_replace.items():
            new_cd = '"displayName": ' + '"' + cd_0 + '"' 
            old_cd = '"displayName": ' + '"' + cd_1 + '"' 
            if cd_match == old_cd:
                secops_dm = re.sub(cd_match, new_cd, secops_dm)
                print(f'replacing {cd_match} w/ {new_cd}')
    secops_cleaned = secops_dm

    with open('secops_ocsf_dm.json', 'w+') as fp:
        secops_dm_js = json.loads(secops_cleaned)
        json.dump(secops_dm_js, fp, indent=2, ensure_ascii=False)
    print(f'Done! secops_ocsf_dm.json file created')
    return secops_cleaned

pull_mappings = generate_mapping(api_url)
secops_final = cleanup_json()
