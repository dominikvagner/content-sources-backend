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


import * as runtime from '../runtime';
import type {
  ApiContentUnitSearchRequest,
  ApiDetectRpmsRequest,
  ApiDetectRpmsResponse,
  ApiRepositoryRpmCollectionResponse,
  ApiSearchRpmResponse,
  ApiSnapshotErrataCollectionResponse,
  ApiSnapshotRpmCollectionResponse,
  ApiSnapshotSearchRpmRequest,
  ErrorsErrorResponse,
} from '../models/index';
import {
    ApiContentUnitSearchRequestFromJSON,
    ApiContentUnitSearchRequestToJSON,
    ApiDetectRpmsRequestFromJSON,
    ApiDetectRpmsRequestToJSON,
    ApiDetectRpmsResponseFromJSON,
    ApiDetectRpmsResponseToJSON,
    ApiRepositoryRpmCollectionResponseFromJSON,
    ApiRepositoryRpmCollectionResponseToJSON,
    ApiSearchRpmResponseFromJSON,
    ApiSearchRpmResponseToJSON,
    ApiSnapshotErrataCollectionResponseFromJSON,
    ApiSnapshotErrataCollectionResponseToJSON,
    ApiSnapshotRpmCollectionResponseFromJSON,
    ApiSnapshotRpmCollectionResponseToJSON,
    ApiSnapshotSearchRpmRequestFromJSON,
    ApiSnapshotSearchRpmRequestToJSON,
    ErrorsErrorResponseFromJSON,
    ErrorsErrorResponseToJSON,
} from '../models/index';

export interface DetectRpmRequest {
    apiDetectRpmsRequest: ApiDetectRpmsRequest;
}

export interface ListRepositoriesRpmsRequest {
    uuid: string;
    limit?: number;
    offset?: number;
    search?: string;
    sortBy?: string;
}

export interface ListSnapshotErrataRequest {
    uuid: string;
    limit?: number;
    offset?: number;
    search?: string;
    type?: string;
    severity?: string;
    sortBy?: string;
}

export interface ListSnapshotRpmsRequest {
    uuid: string;
    limit?: number;
    offset?: number;
    search?: string;
}

export interface ListTemplateRpmsRequest {
    uuid: string;
    limit?: number;
    offset?: number;
    search?: string;
}

export interface SearchRpmRequest {
    apiContentUnitSearchRequest: ApiContentUnitSearchRequest;
}

export interface SearchSnapshotRpmsRequest {
    apiSnapshotSearchRpmRequest: ApiSnapshotSearchRpmRequest;
}

/**
 * 
 */
export class RpmsApi extends runtime.BaseAPI {

    /**
     * This enables users to detect presence of RPMs (Red Hat Package Manager) in a given list of repositories.
     * Detect RPMs presence
     * @deprecated
     */
    async detectRpmRaw(requestParameters: DetectRpmRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ApiDetectRpmsResponse>> {
        if (requestParameters['apiDetectRpmsRequest'] == null) {
            throw new runtime.RequiredError(
                'apiDetectRpmsRequest',
                'Required parameter "apiDetectRpmsRequest" was null or undefined when calling detectRpm().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/rpms/presence`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: ApiDetectRpmsRequestToJSON(requestParameters['apiDetectRpmsRequest']),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ApiDetectRpmsResponseFromJSON(jsonValue));
    }

    /**
     * This enables users to detect presence of RPMs (Red Hat Package Manager) in a given list of repositories.
     * Detect RPMs presence
     * @deprecated
     */
    async detectRpm(requestParameters: DetectRpmRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ApiDetectRpmsResponse> {
        const response = await this.detectRpmRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * List RPMs in a repository.
     * List Repositories RPMs
     */
    async listRepositoriesRpmsRaw(requestParameters: ListRepositoriesRpmsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ApiRepositoryRpmCollectionResponse>> {
        if (requestParameters['uuid'] == null) {
            throw new runtime.RequiredError(
                'uuid',
                'Required parameter "uuid" was null or undefined when calling listRepositoriesRpms().'
            );
        }

        const queryParameters: any = {};

        if (requestParameters['limit'] != null) {
            queryParameters['limit'] = requestParameters['limit'];
        }

        if (requestParameters['offset'] != null) {
            queryParameters['offset'] = requestParameters['offset'];
        }

        if (requestParameters['search'] != null) {
            queryParameters['search'] = requestParameters['search'];
        }

        if (requestParameters['sortBy'] != null) {
            queryParameters['sort_by'] = requestParameters['sortBy'];
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/repositories/{uuid}/rpms`.replace(`{${"uuid"}}`, encodeURIComponent(String(requestParameters['uuid']))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ApiRepositoryRpmCollectionResponseFromJSON(jsonValue));
    }

    /**
     * List RPMs in a repository.
     * List Repositories RPMs
     */
    async listRepositoriesRpms(requestParameters: ListRepositoriesRpmsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ApiRepositoryRpmCollectionResponse> {
        const response = await this.listRepositoriesRpmsRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * List errata in a repository snapshot.
     * List Snapshot Errata
     */
    async listSnapshotErrataRaw(requestParameters: ListSnapshotErrataRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ApiSnapshotErrataCollectionResponse>> {
        if (requestParameters['uuid'] == null) {
            throw new runtime.RequiredError(
                'uuid',
                'Required parameter "uuid" was null or undefined when calling listSnapshotErrata().'
            );
        }

        const queryParameters: any = {};

        if (requestParameters['limit'] != null) {
            queryParameters['limit'] = requestParameters['limit'];
        }

        if (requestParameters['offset'] != null) {
            queryParameters['offset'] = requestParameters['offset'];
        }

        if (requestParameters['search'] != null) {
            queryParameters['search'] = requestParameters['search'];
        }

        if (requestParameters['type'] != null) {
            queryParameters['type'] = requestParameters['type'];
        }

        if (requestParameters['severity'] != null) {
            queryParameters['severity'] = requestParameters['severity'];
        }

        if (requestParameters['sortBy'] != null) {
            queryParameters['sort_by'] = requestParameters['sortBy'];
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/snapshots/{uuid}/errata`.replace(`{${"uuid"}}`, encodeURIComponent(String(requestParameters['uuid']))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ApiSnapshotErrataCollectionResponseFromJSON(jsonValue));
    }

    /**
     * List errata in a repository snapshot.
     * List Snapshot Errata
     */
    async listSnapshotErrata(requestParameters: ListSnapshotErrataRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ApiSnapshotErrataCollectionResponse> {
        const response = await this.listSnapshotErrataRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * List RPMs in a repository snapshot.
     * List Snapshot RPMs
     */
    async listSnapshotRpmsRaw(requestParameters: ListSnapshotRpmsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ApiSnapshotRpmCollectionResponse>> {
        if (requestParameters['uuid'] == null) {
            throw new runtime.RequiredError(
                'uuid',
                'Required parameter "uuid" was null or undefined when calling listSnapshotRpms().'
            );
        }

        const queryParameters: any = {};

        if (requestParameters['limit'] != null) {
            queryParameters['limit'] = requestParameters['limit'];
        }

        if (requestParameters['offset'] != null) {
            queryParameters['offset'] = requestParameters['offset'];
        }

        if (requestParameters['search'] != null) {
            queryParameters['search'] = requestParameters['search'];
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/snapshots/{uuid}/rpms`.replace(`{${"uuid"}}`, encodeURIComponent(String(requestParameters['uuid']))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ApiSnapshotRpmCollectionResponseFromJSON(jsonValue));
    }

    /**
     * List RPMs in a repository snapshot.
     * List Snapshot RPMs
     */
    async listSnapshotRpms(requestParameters: ListSnapshotRpmsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ApiSnapshotRpmCollectionResponse> {
        const response = await this.listSnapshotRpmsRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * List RPMs in a content template.
     * List Template RPMs
     */
    async listTemplateRpmsRaw(requestParameters: ListTemplateRpmsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ApiSnapshotRpmCollectionResponse>> {
        if (requestParameters['uuid'] == null) {
            throw new runtime.RequiredError(
                'uuid',
                'Required parameter "uuid" was null or undefined when calling listTemplateRpms().'
            );
        }

        const queryParameters: any = {};

        if (requestParameters['limit'] != null) {
            queryParameters['limit'] = requestParameters['limit'];
        }

        if (requestParameters['offset'] != null) {
            queryParameters['offset'] = requestParameters['offset'];
        }

        if (requestParameters['search'] != null) {
            queryParameters['search'] = requestParameters['search'];
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/templates/{uuid}/rpms`.replace(`{${"uuid"}}`, encodeURIComponent(String(requestParameters['uuid']))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ApiSnapshotRpmCollectionResponseFromJSON(jsonValue));
    }

    /**
     * List RPMs in a content template.
     * List Template RPMs
     */
    async listTemplateRpms(requestParameters: ListTemplateRpmsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ApiSnapshotRpmCollectionResponse> {
        const response = await this.listTemplateRpmsRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * This enables users to search for RPMs (Red Hat Package Manager) in a given list of repositories.
     * Search RPMs
     */
    async searchRpmRaw(requestParameters: SearchRpmRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Array<ApiSearchRpmResponse>>> {
        if (requestParameters['apiContentUnitSearchRequest'] == null) {
            throw new runtime.RequiredError(
                'apiContentUnitSearchRequest',
                'Required parameter "apiContentUnitSearchRequest" was null or undefined when calling searchRpm().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/rpms/names`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: ApiContentUnitSearchRequestToJSON(requestParameters['apiContentUnitSearchRequest']),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => jsonValue.map(ApiSearchRpmResponseFromJSON));
    }

    /**
     * This enables users to search for RPMs (Red Hat Package Manager) in a given list of repositories.
     * Search RPMs
     */
    async searchRpm(requestParameters: SearchRpmRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Array<ApiSearchRpmResponse>> {
        const response = await this.searchRpmRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * This enables users to search for RPMs (Red Hat Package Manager) in a given list of snapshots.
     * Search RPMs within snapshots
     */
    async searchSnapshotRpmsRaw(requestParameters: SearchSnapshotRpmsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Array<ApiSearchRpmResponse>>> {
        if (requestParameters['apiSnapshotSearchRpmRequest'] == null) {
            throw new runtime.RequiredError(
                'apiSnapshotSearchRpmRequest',
                'Required parameter "apiSnapshotSearchRpmRequest" was null or undefined when calling searchSnapshotRpms().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/snapshots/rpms/names`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: ApiSnapshotSearchRpmRequestToJSON(requestParameters['apiSnapshotSearchRpmRequest']),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => jsonValue.map(ApiSearchRpmResponseFromJSON));
    }

    /**
     * This enables users to search for RPMs (Red Hat Package Manager) in a given list of snapshots.
     * Search RPMs within snapshots
     */
    async searchSnapshotRpms(requestParameters: SearchSnapshotRpmsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Array<ApiSearchRpmResponse>> {
        const response = await this.searchSnapshotRpmsRaw(requestParameters, initOverrides);
        return await response.value();
    }

}
