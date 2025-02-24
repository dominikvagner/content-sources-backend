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
  ApiFetchGPGKeyRequest,
  ApiFetchGPGKeyResponse,
  ErrorsErrorResponse,
} from '../models/index';
import {
    ApiFetchGPGKeyRequestFromJSON,
    ApiFetchGPGKeyRequestToJSON,
    ApiFetchGPGKeyResponseFromJSON,
    ApiFetchGPGKeyResponseToJSON,
    ErrorsErrorResponseFromJSON,
    ErrorsErrorResponseToJSON,
} from '../models/index';

export interface FetchGpgKeyRequest {
    apiFetchGPGKeyRequest: ApiFetchGPGKeyRequest;
}

/**
 * 
 */
export class GpgKeyApi extends runtime.BaseAPI {

    /**
     * Fetch a gpgkey from a remote repo.
     * Fetch gpgkey from URL
     */
    async fetchGpgKeyRaw(requestParameters: FetchGpgKeyRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ApiFetchGPGKeyResponse>> {
        if (requestParameters['apiFetchGPGKeyRequest'] == null) {
            throw new runtime.RequiredError(
                'apiFetchGPGKeyRequest',
                'Required parameter "apiFetchGPGKeyRequest" was null or undefined when calling fetchGpgKey().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/repository_parameters/external_gpg_key/`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: ApiFetchGPGKeyRequestToJSON(requestParameters['apiFetchGPGKeyRequest']),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ApiFetchGPGKeyResponseFromJSON(jsonValue));
    }

    /**
     * Fetch a gpgkey from a remote repo.
     * Fetch gpgkey from URL
     */
    async fetchGpgKey(requestParameters: FetchGpgKeyRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ApiFetchGPGKeyResponse> {
        const response = await this.fetchGpgKeyRaw(requestParameters, initOverrides);
        return await response.value();
    }

}
