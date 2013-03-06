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
    var xml2js = require('xml2js');
    var xmlParser = new xml2js.Parser(xml2js.defaults["0.2"]);
    var util = require('util');
    var data;
    var debug = false;

    /**
    * Translate input file from XACML to editor JSON schema
    * @function
    * @param policyFile XACML file to read
    * @param jsonFile JSON file to write
    */
    var policy2editor = function(policyFile, jsonFile) {

        if (policyFile === null || policyFile === undefined) {
            console.log('policy file parameter is missing');
            return false;
        }
        try {
            var xmlPolicy = fs.readFileSync(policyFile);
            // Parse manifest
            parseFile(xmlPolicy);
        } catch (error) {
            console.log(error);
            return false;
        }

        var output = {};
        // read root tag
        if (data['policy-set']) {
            output = readPolicySet(data['policy-set']);
        } else if (data['policy']) {
            output = readPolicy(data['policy']);
        } else {
            return false;
        }

        if (debug === true) {
            console.log(util.inspect(output, false, null));
        }
        try {
            fs.writeFileSync(jsonFile, JSON.stringify(output));
        } catch (error) {
            console.log(error);
            return false;
        }
        return true;
    };

    /**
    * Translate policy set from XACML to editor JSON schema
    * @function
    * @param policySet policy set to translate
    */
    var readPolicySet = function(policySet) {
        var output = {};
        output['policy-set'] = {};

        // policy set attributes
        if (policySet.$) {
            if (policySet.$.combine) {
                output['policy-set'].combine = policySet.$.combine;
            }
            if (policySet.$.description) {
                output['policy-set'].description = policySet.$.description;
            }
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
    * Translate policy from XACML to editor JSON schema
    * @function
    * @param policy policy to translate
    */
    var readPolicy = function (policy) {
        var tmp = {};

        // policy attributes
        if (policy.$) {
            if (policy.$.combine) {
                tmp.combine = policy.$.combine;
            }
            if (policy.$.description) {
                tmp.description = policy.$.description;
            }
        }

        // policy target
        tmp.subject = [];
        if (policy.target) {
            for (var i = 0; i < policy.target[0].subject[0]['subject-match']
                .length; i++) {

                tmp.subject.push(policy.target[0].subject[0]['subject-match']
                    [i].$)
            }
        }

        // policy rules
        tmp.rule = [];
        if (policy.rule) {
            for (var i = 0; i < policy.rule.length; i++) {
                tmp.rule[i] = {};
                tmp.rule[i].effect = policy.rule[i].$.effect;
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
    * Translate condition from XACML to editor JSON schema
    * @function
    * @param condition condition to translate
    */
    var readCondition = function(condition) {
        var tmp = {};

        // condition attributes
        if (condition.$ && condition.$.combine) {
            tmp.combine = condition.$.combine;
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
                tmp['resource-match'].push(condition['resource-match'][i].$);
            }
        }
        return tmp;
    };

    /**
    * Parse XML file
    * @function
    * @param xmlFile XML file to parse
    */
    var parseFile = function (xmlFile) {
        xmlParser.parseString(xmlFile, function(err, parsedData) {
            if (err === undefined || err === null) {
                data = parsedData;
            } else {
                console.log(err);
                return false;
            }
        });
    };

    exports.policy2editor = policy2editor;

}());
