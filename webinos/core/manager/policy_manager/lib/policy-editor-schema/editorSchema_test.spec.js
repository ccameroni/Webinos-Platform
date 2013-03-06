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

var fs = require('fs');
var path = require('path');
var p2e = require (path.join(__dirname, './policy2editor.js'));
var policyFile1 = path.join(__dirname, 'policyExample.xml');
var jsonFile = path.join(__dirname, 'editorSchema.json');

p2e.policy2editor(policyFile1, jsonFile);

var policyFile2 = path.join(__dirname, 'policyOutput.xml');
var e2p = require (path.join(__dirname, './editor2policy.js'));

e2p.editor2policy(jsonFile, policyFile2);
