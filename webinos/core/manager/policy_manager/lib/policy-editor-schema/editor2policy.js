/*******************************************************************************
 *  Code contributed to the webinos project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2013 Torsec -Computer and network security group-
 * Politecnico di Torino
 *
 ******************************************************************************/


(function () {
    "use strict";

    var fs = require('fs');
    var path = require('path');
    var convert2xml = require('data2xml')({attrProp : '$', valProp : '_'});
    var util = require('util');
    var data;
    var debug = false;

    /**
    * Translate input file from editor JSON schema to XACML
    * @function
    * @param jsonFile JSON file to read
    * @param policyFile XACML file to write
    */
    var editor2policy = function(jsonFile, policyFile) {

        if (jsonFile === null || jsonFile === undefined) {
            console.log('json file parameter is missing');
            return null;
        }
        try {
            data = JSON.parse(fs.readFileSync(jsonFile, 'utf-8'));
        } catch (error) {
            console.log(error);
            return false;
        }

        var output = {};

        // policy set root tag
        if (data['policy-set']) {
            output = readPolicySet(data['policy-set']);
            try {
                var xml = convert2xml('policy-set', output['policy-set']);
            } catch (error) {
                console.log(error);
                return false;
            }

        // policy root tag
        } else if (data['policy']) {
            output = (readPolicy(data['policy']));
            try {
                var xml = convert2xml('policy', output['policy']);
            } catch (error) {
                console.log(error);
                return false;
            }
        }

        if (debug === true) {
            console.log(util.inspect(output, false, null));
        }

        if (xml) {
            try {
                xml = xml.replace('<?xml version=\"1.0\" encoding=\"utf-8\"?>\n'
                    , '');
                fs.writeFileSync(policyFile, xml);
            } catch (error) {
                console.log(error);
                return false;
            }
            return true;
        } else {
            return false;
        }
    };

    /**
    * Translate policy set from editor JSON schema to XACML
    * @function
    * @param policySet policy set to translate
    */
    var readPolicySet = function(policySet) {
        var output = {};
        output['policy-set'] = {};

        // policy set attributes
        output['policy-set'].$ = {};
        if (policySet.combine) {
            output['policy-set'].$.combine = policySet.combine;
        }
        if (policySet.description) {
            output['policy-set'].$.description = policySet.description;
        }

        // policies
        if (policySet.policy) {
            output['policy-set'].policy = [];
            for (var i = 0; i < policySet.policy.length; i++) {
                output['policy-set'].policy
                    .push(readPolicy(policySet.policy[i]));
            }
        }

        // nested policy sets
        if (policySet['policy-set']) {
            output['policy-set']['policy-set'] = [];
            for (var i = 0; i < policySet['policy-set'].length; i++) {
                output['policy-set']['policy-set']
                    .push(readPolicySet(policySet['policy-set'][i]));
            }
        }
        return output;
    };

    /**
    * Translate policy from editor JSON schema to XACML
    * @function
    * @param policy policy to translate
    */
    var readPolicy = function (policy) {
        var tmp = {};

        // policy attributes
        tmp.$ = {};
        if (policy.combine) {
            tmp.$.combine = policy.combine;
        }
        if (policy.description) {
            tmp.$.description = policy.description;
        }

        // policy target
        if (policy.subject && policy.subject[0]) {
            tmp.target = [];
            tmp.target[0] = {};
            tmp.target[0].subject = [];
            tmp.target[0].subject[0]= {};
            tmp.target[0].subject[0]['subject-match'] = [];
            for (var i = 0; i < policy.subject.length; i++) {
                tmp.target[0].subject[0]['subject-match'][i] = {};
                tmp.target[0].subject[0]['subject-match'][i].$ = {};
                tmp.target[0].subject[0]['subject-match'][i].$ =
                    policy.subject[i];
            }
        }

        // policy rules
        tmp.rule = [];
        if (policy.rule) {
            for (var i = 0; i < policy.rule.length; i++) {
                tmp.rule[i] = {};
                tmp.rule[i].$ = {};
                tmp.rule[i].$.effect = policy.rule[i].effect;
                if (policy.rule[i].condition) {
                    tmp.rule[i].condition = [];
                    for (var j = 0; j < policy.rule[i].condition.length; j++) {
                        tmp.rule[i].condition.push(readCondition(policy.rule[i]
                            .condition[j]));
                    }
                }
            }
        }
        return tmp;
    };

    /**
    * Translate condition from editor JSON schema to XACML
    * @function
    * @param condition condition to translate
    */
    var readCondition = function(condition) {
        var tmp = {};

        // condition attributes
        tmp.$ = {};
        if (condition.combine) {
            tmp.$.combine = condition.combine;
        }

        // nested conditions
        if (condition.condition) {
            tmp.condition = [];
            for (var i = 0; i < condition.condition.length; i++) {
                readCondition(condition.condition[i], tmp.condition[i]);
            }

        // resource matches
        } else if (condition['resource-match']) {
            tmp['resource-match'] = [];
            for (var i = 0; i < condition['resource-match'].length; i++) {
                tmp['resource-match'][i] = {};
                tmp['resource-match'][i].$ = condition['resource-match'][i];
            }
        }
        return tmp;
    };

    exports.editor2policy = editor2policy;

}());
