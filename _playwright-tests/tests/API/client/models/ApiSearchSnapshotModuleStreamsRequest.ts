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
 * @interface ApiSearchSnapshotModuleStreamsRequest
 */
export interface ApiSearchSnapshotModuleStreamsRequest {
    /**
     * List of rpm names to restrict returned modules
     * @type {Array<string>}
     * @memberof ApiSearchSnapshotModuleStreamsRequest
     */
    rpmNames: Array<string>;
    /**
     * Search string to search module names
     * @type {string}
     * @memberof ApiSearchSnapshotModuleStreamsRequest
     */
    search?: string;
    /**
     * SortBy sets the sort order of the result
     * @type {string}
     * @memberof ApiSearchSnapshotModuleStreamsRequest
     */
    sortBy?: string;
    /**
     * List of snapshot UUIDs to search
     * @type {Array<string>}
     * @memberof ApiSearchSnapshotModuleStreamsRequest
     */
    uuids: Array<string>;
}

/**
 * Check if a given object implements the ApiSearchSnapshotModuleStreamsRequest interface.
 */
export function instanceOfApiSearchSnapshotModuleStreamsRequest(value: object): value is ApiSearchSnapshotModuleStreamsRequest {
    if (!('rpmNames' in value) || value['rpmNames'] === undefined) return false;
    if (!('uuids' in value) || value['uuids'] === undefined) return false;
    return true;
}

export function ApiSearchSnapshotModuleStreamsRequestFromJSON(json: any): ApiSearchSnapshotModuleStreamsRequest {
    return ApiSearchSnapshotModuleStreamsRequestFromJSONTyped(json, false);
}

export function ApiSearchSnapshotModuleStreamsRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): ApiSearchSnapshotModuleStreamsRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'rpmNames': json['rpm_names'],
        'search': json['search'] == null ? undefined : json['search'],
        'sortBy': json['sort_by'] == null ? undefined : json['sort_by'],
        'uuids': json['uuids'],
    };
}

export function ApiSearchSnapshotModuleStreamsRequestToJSON(json: any): ApiSearchSnapshotModuleStreamsRequest {
    return ApiSearchSnapshotModuleStreamsRequestToJSONTyped(json, false);
}

export function ApiSearchSnapshotModuleStreamsRequestToJSONTyped(value?: ApiSearchSnapshotModuleStreamsRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'rpm_names': value['rpmNames'],
        'search': value['search'],
        'sort_by': value['sortBy'],
        'uuids': value['uuids'],
    };
}

