/* tslint:disable */
/* eslint-disable */
/**
 * ContentSourcesBackend
 * The API for the repositories of the content sources that you can use to create and manage repositories between third-party applications and the [Red Hat Hybrid Cloud Console](https://console.redhat.com). With these repositories, you can build and deploy images using Image Builder for Cloud, on-Premise, and Edge. You can handle tasks, search for required RPMs, fetch a GPGKey from the URL, and list the features within applications. 
 *
 * The version of the OpenAPI document: v1.0.0
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface ApiModuleInfoResponse
 */
export interface ApiModuleInfoResponse {
    /**
     * Architecture of the module
     * @type {string}
     * @memberof ApiModuleInfoResponse
     */
    arch?: string;
    /**
     * Context of the module
     * @type {string}
     * @memberof ApiModuleInfoResponse
     */
    context?: string;
    /**
     * Description of the module
     * @type {string}
     * @memberof ApiModuleInfoResponse
     */
    description?: string;
    /**
     * Name of the module
     * @type {string}
     * @memberof ApiModuleInfoResponse
     */
    name?: string;
    /**
     * Stream of the module
     * @type {string}
     * @memberof ApiModuleInfoResponse
     */
    stream?: string;
    /**
     * Type of rpm (can be either 'package' or 'module')
     * @type {string}
     * @memberof ApiModuleInfoResponse
     */
    type?: string;
    /**
     * Version of the module
     * @type {string}
     * @memberof ApiModuleInfoResponse
     */
    version?: string;
}

/**
 * Check if a given object implements the ApiModuleInfoResponse interface.
 */
export function instanceOfApiModuleInfoResponse(value: object): value is ApiModuleInfoResponse {
    return true;
}

export function ApiModuleInfoResponseFromJSON(json: any): ApiModuleInfoResponse {
    return ApiModuleInfoResponseFromJSONTyped(json, false);
}

export function ApiModuleInfoResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): ApiModuleInfoResponse {
    if (json == null) {
        return json;
    }
    return {
        
        'arch': json['arch'] == null ? undefined : json['arch'],
        'context': json['context'] == null ? undefined : json['context'],
        'description': json['description'] == null ? undefined : json['description'],
        'name': json['name'] == null ? undefined : json['name'],
        'stream': json['stream'] == null ? undefined : json['stream'],
        'type': json['type'] == null ? undefined : json['type'],
        'version': json['version'] == null ? undefined : json['version'],
    };
}

export function ApiModuleInfoResponseToJSON(json: any): ApiModuleInfoResponse {
    return ApiModuleInfoResponseToJSONTyped(json, false);
}

export function ApiModuleInfoResponseToJSONTyped(value?: ApiModuleInfoResponse | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'arch': value['arch'],
        'context': value['context'],
        'description': value['description'],
        'name': value['name'],
        'stream': value['stream'],
        'type': value['type'],
        'version': value['version'],
    };
}

