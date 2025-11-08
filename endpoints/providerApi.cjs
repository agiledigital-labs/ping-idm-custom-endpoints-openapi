// @ts-expect-error - TS doesn't have context of native IDM libs
const _ = require("lib/lodash");

const javaImports = JavaImporter(
  java.util.UUID,
  java.security.cert.CertificateFactory,
  java.io.ByteArrayInputStream,
  java.lang.String,
  java.text.SimpleDateFormat,
  java.util.Date,
  java.util.Calendar
);

/**
 * API PKI cert revocation reasons. We only use 5 but for any future flexibility the others are provided
 *
 */
const certOperationReasons = {
  unspecified: 0,
  keyCompromise: 1,
  cACompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  removeFromCRL: 8,
  privilegeWithdrawn: 9,
  aACompromise: 10,
};

const userManagedObjectKey = "managed/alpha_user";
const deviceManagedObjectKey = "managed/alpha_digital_partner_device";
const dpOrgManagedObjectKey = "managed/alpha_digital_partner_organisation";
const certificateObjectKey = "managed/alpha_digital_partner_certificate";

// TODO add a generic inferred from the validator that is passed to the request context
/**
 * @typedef {{
 *  body: typeof request.content,
 *  headers: typeof context.http.headers,
 *  query: typeof request.additionalParameters;
 * }} RequestContext
 */

/**
 * @typedef {{
 *  name: string;
 *  type: "body" | "query";
 *  required: boolean;
 *  pattern?: RegExp;
 *  errorMessage?: (validator, value) => string;
 * }} Validator
 */

/**
 * @param {object} args
 * @param {Validator[]} args.validators
 * @param {(request: RequestContext) => PolicyResult} args.policy
 * @param {(request: RequestContext) => object} args.operation
 */
function buildApiEndpoint(args) {
  const { validators, policy, operation } = args;
  return {
    contentType: "application/json",
    validators,
    policy,
    operation,
  };
}

const apis = /** @type {const} */ ({
  v1: {
    "register-device": {
      POST: buildApiEndpoint({
        validators: [
          {
            name: "name",
            type: "body",
            required: true,
            pattern: /^[a-zA-Z0-9-_. ]+$/,
            errorMessage: (validator, value) =>
              `'${value}' is not a valid device name '${validator.name}'.`,
          },
          {
            name: "environment",
            type: "body",
            required: true,
            pattern: /^(test|prod)$/,
            errorMessage: (validator, value) =>
              `'${value}' is not a valid device environment '${validator.name}'.`,
          },
          {
            name: "abn",
            type: "body",
            required: true,
            pattern: /^[1-9][0-9]{10}$/,
            errorMessage: (validator, value) =>
              `'${value}' is not in valid organisation ABN format '${validator.name}'.`,
          },
          {
            name: "type",
            type: "body",
            required: true,
            pattern: /^[a-zA-Z0-9-_. ]+$/,
            errorMessage: (validator, value) =>
              `'${value}' is not a valid device type '${validator.name}'.`,
          },
          {
            name: "aggregatorAbn",
            type: "body",
            required: false,
            pattern: /^[1-9][0-9]{10}$/,
            errorMessage: (validator, value) =>
              `'${value}' is not in valid organisation ABN format '${validator.name}'.`,
          },
        ],
        policy: registerDevicePolicy,
        operation: registerDevice,
      }),
    },
    "activate-device": {
      POST: buildApiEndpoint({
        validators: [
          {
            name: "csr",
            type: "body",
            required: true,
            pattern:
              /^-----BEGIN NEW CERTIFICATE REQUEST-----.*-----END NEW CERTIFICATE REQUEST-----$/,
            errorMessage: (validator, value) =>
              `'${value}' is not in valid CSR format ${validator.name}'.`,
          },
          {
            name: "deviceId",
            type: "body",
            required: true,
            pattern: /^[a-zA-Z0-9-_. ]+$/,
            errorMessage: (validator, value) =>
              `'${value}' is not a valid device UUID '${validator.name}'.`,
          },
        ],
        policy: activateDevicePolicy,
        operation: activateDeviceHandler,
      }),
    },
    "add-cert": {
      POST: buildApiEndpoint({
        validators: [
          {
            name: "csr",
            type: "body",
            required: true,
            pattern:
              /^-----BEGIN NEW CERTIFICATE REQUEST-----.*-----END NEW CERTIFICATE REQUEST-----$/,
            errorMessage: (validator, value) =>
              `'${value}' is not in valid CSR format ${validator.name}'.`,
          },
          {
            name: "deviceId",
            type: "body",
            required: true,
            pattern: /^[a-zA-Z0-9-_. ]+$/,
            errorMessage: (validator, value) =>
              `'${value}' is not a valid device UUID '${validator.name}'.`,
          },
        ],
        policy: addCertPolicy,
        operation: addCert,
      }),
    },
    "revoke-cert": {
      POST: buildApiEndpoint({
        validators: [
          {
            name: "oauthClientId",
            type: "body",
            required: true,
            pattern: /^[a-zA-Z0-9-_. ]+$/,
            errorMessage: (validator, value) =>
              `'${value}' is not a valid device UUID '${validator.name}'.`,
          },
        ],
        policy: revokeCertPolicy,
        operation: revokeCert,
      }),
    },
    "register-and-activate": {
      POST: buildApiEndpoint({
        validators: [
          {
            name: "name",
            type: "body",
            required: true,
            pattern: /^[a-zA-Z0-9-_. ]+$/,
            errorMessage: (validator, value) =>
              `'${value}' is not a valid device name '${validator.name}'.`,
          },
          {
            name: "environment",
            type: "body",
            required: true,
            pattern: /^(test|prod)$/,
            errorMessage: (validator, value) =>
              `'${value}' is not a valid device environment '${validator.name}'.`,
          },
          {
            name: "abn",
            type: "body",
            required: true,
            pattern: /^[1-9][0-9]{10}$/,
            errorMessage: (validator, value) =>
              `'${value}' is not in valid organisation ABN format '${validator.name}'.`,
          },
          {
            name: "type",
            type: "body",
            required: true,
            pattern: /^[a-zA-Z0-9-_. ]+$/,
            errorMessage: (validator, value) =>
              `'${value}' is not a valid device type '${validator.name}'.`,
          },
          {
            name: "csr",
            type: "body",
            required: true,
            pattern:
              /^-----BEGIN NEW CERTIFICATE REQUEST-----.*-----END NEW CERTIFICATE REQUEST-----$/,
            errorMessage: (validator, value) =>
              `'${value}' is not in valid CSR format ${validator.name}'.`,
          },
        ],
        policy: registerActivatePolicy,
        operation: registerActivate,
      }),
    },
    "retrieve-device-list": {
      GET: buildApiEndpoint({
        validators: [
          {
            name: "abn",
            type: "query",
            required: true,
          },
        ],
        policy: getDeviceListPolicy,
        operation: getDeviceList,
      }),
    },
    "retrieve-device-detail": {
      GET: buildApiEndpoint({
        validators: [
          {
            name: "deviceId",
            type: "query",
            required: true,
          },
        ],
        policy: getDeviceDetailPolicy,
        operation: getDeviceDetail,
      }),
    },
    "get-aggregator-list": {
      GET: buildApiEndpoint({
        validators: [
          {
            name: "abn",
            type: "query",
            required: true,
          },
        ],
        policy: getAggregatorListPolicy,
        operation: getAggregatorList,
      }),
    },
    "delete-device": {
      POST: buildApiEndpoint({
        validators: [
          {
            name: "deviceId",
            type: "body",
            required: true,
          },
        ],
        policy: deleteDevicePolicy,
        operation: deleteDevice,
      }),
    },
  },
});

/**
 * @typedef {{
 * _id: string,
 * custom_memberOfDpOrg: {
 *  _ref: string,
 *  abn: string,
 * }[] | undefined,
 * }} User
 */

/**
 * @typedef {{
 * _id: string,
 * name: string,
 * abn: string,
 * type: "provider" | "aggregator",
 * approvedEnvironment?: "test" | "prod",
 * vendorTestOrgNdisNumber?: string,
 * }} DpOrganisation
 */

/**
 * @typedef {{
 * _id: string,
 * ciamId: string,
 * name: string,
 * environment: "test" | "prod",
 * abn: string,
 * type: string,
 * status?: "active" | "inactive",
 * certificates?: {_ref: string, _refResourceId: string}[],
 * }} Device
 */

/**
 * @typedef {{
 * name: string,
 * environment: "test" | "prod",
 * abn: string,
 * type: string,
 * status?: "active" | "inactive",
 * organisation?: {_ref: string},
 * aggregator?: {_ref: string},
 * }} DeviceCreation
 */

/**
 * @typedef {{
 * pkiToken: string,
 * pkiEndpoint: string,
 * pkiRevokeEndpoint: string,
 * pkiTemplateId: string,
 * caName: string,
 * pkiCaId: string,
 * vendorTestIsMulesoftIntegrationEnabled: boolean,
 * vendorProdIsMulesoftIntegrationEnabled: boolean,
 * vendorTestMulesoftDomain: string,
 * vendorProdMulesoftDomain: string,
 * expiryMonths: number,
 * vendorTestMulesoftCredentials: object,
 * vendorProdMulesoftCredentials: object,
 * }} RetrieveConfig
 */

/**
 * @typedef {{
 * userId: string,
 * scopes: array,
 * manageDeviceScopes: string
 * manageCertificateScopes: string
 * tokenClientId: string
 * }} RetrieveTokenDetails
 */

/**
 * Safely parses an integer from an environment string variable.
 *
 * @param {unknown} value - The environment string variable to parse.
 * @returns {{success: true, value?: number}
 * | {success: false, error?: string}}
 */
function safeParseIntEsv(value) {
  try {
    const parsedValue = parseInt(String(value), 10);

    if (isNaN(parsedValue)) {
      return {
        success: false,
        error: `[${value}] is of type string but resulted in NaN when trying to parse as integer`,
      };
    }

    return {
      success: true,
      value: parsedValue,
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Booleans ESVs don't work in IDM, so must be coerced
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function coerceBooleanEsv(value) {
  return String(value) === "true";
}

/**
 * Retrieves the PKI configuration for the service.
 *
 * @returns {RetrieveConfig} The configuration object for PKI setup.
 */
function retrieveConfig() {
  const pkiToken = identityServer.getProperty("esv.provider_api.pki_secret");
  const pkiEndpoint = identityServer.getProperty(
    "esv.provider_api.pki.cert.endpoint"
  );
  const pkiTemplateId = identityServer.getProperty(
    "esv.provider_api.pki.template_id"
  );
  const pkiRevokeEndpoint = identityServer.getProperty(
    "esv.provider_api.pki.cert.revoke.endpoint"
  );
  const caName = identityServer.getProperty("esv.provider_api.pki.ca.name");
  const pkiCaId = identityServer.getProperty("esv.provider_api.pki.ca_id");
  const maybeExpiryMonths = safeParseIntEsv(
    identityServer.getProperty("esv.provider_api.device.expiry.date")
  );
  if (!maybeExpiryMonths.success) {
    logger.error(
      `Failed to parse expiryMonths as integer: [${maybeExpiryMonths.error}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Invalid configuration",
    };
  }
  const expiryMonths = maybeExpiryMonths.value;
  if (
    !pkiToken ||
    !pkiEndpoint ||
    !pkiTemplateId ||
    !pkiCaId ||
    !pkiRevokeEndpoint ||
    !caName ||
    !expiryMonths
  ) {
    logger.error(
      "Missing required PKI configuration, [{}]",
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Invalid configuration",
    };
  }
  const vendorProdIsMulesoftIntegrationEnabled = identityServer.getProperty(
    "esv.provider_api.mulesoft.toggle"
  );
  const vendorProdMulesoftDomain = identityServer.getProperty(
    "esv.mulesoft.api.base_url"
  );
  const vendorProdMulesoftCredentials = {
    client_id: identityServer.getProperty("esv.mulesoft.api.client_id"),
    client_secret: identityServer.getProperty("esv.mulesoft.api.client_secret"),
    "CF-Access-Client-Id": identityServer.getProperty(
      "esv.mulesoft.api.cloudflare.client_id"
    ),
    "CF-Access-Client-Secret": identityServer.getProperty(
      "esv.mulesoft.api.cloudflare.client_secret"
    ),
  };
  if (
    !vendorProdMulesoftDomain ||
    !vendorProdMulesoftCredentials.client_id ||
    !vendorProdMulesoftCredentials.client_secret ||
    !vendorProdMulesoftCredentials["CF-Access-Client-Id"] ||
    !vendorProdMulesoftCredentials["CF-Access-Client-Secret"]
  ) {
    logger.error(
      "Missing required Mulesoft configuration for Vendor Prod, [{}]",
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Invalid configuration",
    };
  }

  const vendorTestIsMulesoftIntegrationEnabled = identityServer.getProperty(
    "esv.provider_api.mulesoft.toggle.vendor_test"
  );
  const vendorTestMulesoftDomain = identityServer.getProperty(
    "esv.provider_api.mulesoft_api.base_url.vendor_test"
  );
  const vendorTestMulesoftCredentials = {
    client_id: identityServer.getProperty(
      "esv.provider_api.mulesoft_api.client_id.vendor_test"
    ),
    client_secret: identityServer.getProperty(
      "esv.provider_api.mulesoft_api.client_secret.vendor_test"
    ),
    "CF-Access-Client-Id": identityServer.getProperty(
      "esv.provider_api.mulesoft_api.cloudflare.client_id.vendor_test"
    ),
    "CF-Access-Client-Secret": identityServer.getProperty(
      "esv.provider_api.mulesoft_api.cloudflare.client_secret.vendor_test"
    ),
  };
  if (
    !vendorTestMulesoftDomain ||
    !vendorTestMulesoftCredentials.client_id ||
    !vendorTestMulesoftCredentials.client_secret ||
    !vendorTestMulesoftCredentials["CF-Access-Client-Id"] ||
    !vendorTestMulesoftCredentials["CF-Access-Client-Secret"]
  ) {
    logger.error(
      "Missing required Mulesoft configuration for Vendor Test, [{}]",
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Invalid configuration",
    };
  }

  return {
    pkiToken,
    expiryMonths,
    pkiEndpoint,
    pkiRevokeEndpoint,
    pkiTemplateId,
    pkiCaId,
    caName,
    vendorProdIsMulesoftIntegrationEnabled: coerceBooleanEsv(
      vendorProdIsMulesoftIntegrationEnabled
    ),
    vendorProdMulesoftDomain,
    vendorProdMulesoftCredentials,
    vendorTestIsMulesoftIntegrationEnabled: coerceBooleanEsv(
      vendorTestIsMulesoftIntegrationEnabled
    ),
    vendorTestMulesoftDomain,
    vendorTestMulesoftCredentials,
  };
}

/**
 * Retrieves the user access token details.
 *
 * @returns {RetrieveTokenDetails} The user access token details.
 */
function retrieveTokenDetails() {
  const tokenInfoPath = context.parent.parent.parent.parent.parent;
  const userId = tokenInfoPath.rawInfo.user_id;
  const scopes = tokenInfoPath.scopes || [];
  const tokenClientId = tokenInfoPath.rawInfo.client_id;
  const manageDeviceScopes = identityServer.getProperty(
    "esv.provider_api.registration_portal.scopes_manage_device"
  );
  const manageCertificateScopes = identityServer.getProperty(
    "esv.provider_api.registration_portal.scopes_manage_certificate"
  );

  if (!manageDeviceScopes || !manageCertificateScopes) {
    logger.error(
      "Missing required token configuration, [{}]",
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Invalid configuration",
    };
  }

  return {
    userId,
    scopes,
    manageDeviceScopes,
    manageCertificateScopes,
    tokenClientId,
  };
}

/**
 * @typedef {{
 *   code: 400 | 404 | 403 | 500;
 *   message: string;
 * }} HttpError
 */

/**
 * @typedef {{ success: true; }
 * | { success: false; error: HttpError; }} PolicyResult
 */

/**
 * @typedef {{ success: true; isMember: boolean; }
 * | { success: false; error: HttpError; }} MemberPolicyResult
 */

/**
 * Check if the user belongs to an organisation
 * @param {User} userData - user data
 * @param {string} abn - Digital Partner Organisation ABN
 * @returns {MemberPolicyResult}
 */
function checkUserOrgMembership(userData, abn) {
  try {
    // Validate inputs
    if (!userData || !abn) {
      return {
        success: false,
        error: {
          code: 400,
          message: "Bad Request: user data and org abn are required",
        },
      };
    }

    // Check the user's organisations relationship
    const userOrganisations = userData.custom_memberOfDpOrg || [];
    const isMember = userOrganisations.some(function (orgRef) {
      return orgRef.abn === abn;
    });

    return {
      success: true,
      isMember: isMember,
    };
  } catch (error) {
    logger.error(
      `Error checking user-organisation membership for userId [${userData._id}] and ABN [${abn}]: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );

    return {
      success: false,
      error: {
        code: 500,
        message: "Internal Server Error",
      },
    };
  }
}

/**
 * Check if a user is in the device's organisation or user Organisation
 * @param {string} deviceId - the device ID
 * @param {User} userData - The user data
 * @returns {MemberPolicyResult}
 */
function checkUserDeviceMembership(deviceId, userData) {
  try {
    // Validate inputs
    if (!deviceId || !userData) {
      return {
        success: false,
        error: {
          code: 400,
          message: "Bad Request: user data and org abn are required",
        },
      };
    }

    // Fetch the device
    const device = /** @type {Device} */ (
      openidm.read(`${deviceManagedObjectKey}/${deviceId}`, null, [
        "organisation/*",
        "aggregator/*",
      ])
    );

    if (!device) {
      return {
        success: false,
        error: {
          code: 404,
          message: `Device not found: [${deviceId}]`,
        },
      };
    }

    // Get the Provider organisation associated with the device
    const orgRef = device.organisation;
    if (!orgRef || !orgRef._ref) {
      return {
        success: false,
        error: {
          code: 404,
          message: `Device [${deviceId}] is not associated with any organisation`,
        },
      };
    }

    // Extract organisation ID from reference
    const orgId = orgRef._ref.split("/").pop();

    // Check if user is a member of the organisation
    const userOrganisations = userData.custom_memberOfDpOrg || [];
    var isMember = userOrganisations.some(function (orgRef) {
      return orgRef._ref === `${dpOrgManagedObjectKey}/${orgId}`;
    });

    if (!isMember) {
      logger.info(
        `Can't find membership for userId [${userData._id}] and deviceId [${deviceId}] in Provider Organisation [${device.organisation ? device.organisation.abn : "unknown"
        }]. Search for aggregator organisation. [{}]`,
        endpointEnrichLog()
      );

      // Check user is a member of the aggregator organisation
      // Get the aggregator organisation associated with the device
      const aggregatorOrgRef = device.aggregator;
      if (aggregatorOrgRef && aggregatorOrgRef._ref) {
        // Extract organisation ID from reference
        const aggregatorOrgId = aggregatorOrgRef._ref.split("/").pop();

        // Check if user is a member of the aggregator organisation
        isMember = userOrganisations.some(function (orgRef) {
          return orgRef._ref === `${dpOrgManagedObjectKey}/${aggregatorOrgId}`;
        });
      }
    }

    return {
      success: true,
      isMember: isMember,
    };
  } catch (error) {
    logger.error(
      `Error checking user-device membership for userId [${userData._id}] and deviceId [${deviceId}]: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );

    return {
      success: false,
      error: {
        code: 500,
        message: "Internal Server Error",
      },
    };
  }
}

/**
 * Check if a user is in the device's organisation based on a certificate
 * @param {string} certificateId - the certificate ID
 * @param {User} userData - The user data
 * @returns {MemberPolicyResult}
 */
function checkUserCertificateMembership(certificateId, userData) {
  try {
    // Validate inputs
    if (!certificateId || !userData) {
      return {
        success: false,
        error: {
          code: 400,
          message: "Bad Request: certificate Id and user data are required",
        },
      };
    }

    // Fetch the certificate
    const certificate = /** @type {certificate} */ (
      openidm.read(`${certificateObjectKey}/${certificateId}`, null, [
        "device/*",
      ])
    );

    if (!certificate) {
      return {
        success: false,
        error: {
          code: 404,
          message: `certificate not found: [${certificateId}]`,
        },
      };
    }

    // Get the device associated with the certificate
    const deviceRef = certificate.device;
    if (!deviceRef || !deviceRef._ref) {
      return {
        success: false,
        error: {
          code: 404,
          message: `Certificate [${certificateId}] is not associated with any device`,
        },
      };
    }

    // Extract device ID from reference
    const deviceId = deviceRef._ref.split("/").pop();

    // Check if user is a member of the organisation based on device ID
    return checkUserDeviceMembership(deviceId, userData);
  } catch (error) {
    logger.error(
      `Error checking user-device membership for userId [${userData._id}] and certificateId [${certificateId}]: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );

    return {
      success: false,
      error: {
        code: 500,
        message: "Internal Server Error",
      },
    };
  }
}

/**
 * Validate the required scopes are included
 * @param {string} rawRequiredScopes - The required scopes
 * @param {string[]} scopes - The scopes in the access token
 * @returns {boolean} true if the required scopes are in the access token
 * scopes, false otherwise.
 */
function validateScope(rawRequiredScopes, scopes) {
  // Make sure scopes is an javascript array
  // @ts-expect-error - TS doesn't know about IDM's Java List type
  const scopesArray = [].concat(Array.from(scopes));
  const requiredScopesArray = JSON.parse(rawRequiredScopes);

  return (
    requiredScopesArray.filter((scope) => scopesArray.includes(scope))
      .length === requiredScopesArray.length
  );
}

/**
 * @typedef {{
 *  userId: string;
 *  tokenClientId: string;
 *  manageDeviceScopes: string;
 *  manageCertificateScopes: string;
 *  scopes: string[];
 * }} TokenDetails
 */

/**
 * Validate the required scopes are included and user/org relationship
 * @param {TokenDetails} tokenDetails - The incoming OAuth access token details
 * @param {string} abn - The org abn
 * @returns {PolicyResult}
 */
function userOrgRelationshipPolicy(tokenDetails, abn) {
  // Check if the access token is with the required scopes
  if (!validateScope(tokenDetails.manageDeviceScopes, tokenDetails.scopes)) {
    logger.warn(
      `Missing required scope [${tokenDetails.manageDeviceScopes}] in the scopes [${tokenDetails.scopes}], [{}]`,
      endpointEnrichLog()
    );

    return {
      success: false,
      error: {
        code: 403,
        message: "Forbidden: Missing required scope",
      },
    };
  }

  // Query the user to ensure they exist
  const user = openidm.read(
    `${userManagedObjectKey}/${tokenDetails.userId}`,
    null,
    ["custom_memberOfDpOrg/*"]
  );

  if (!user) {
    return {
      success: false,
      error: {
        code: 404,
        message: `User not found: [${tokenDetails.userId}]`,
      },
    };
  }

  // Check is the user is a member of the organisation
  const checkUser = checkUserOrgMembership(user, abn);

  if (!checkUser.success) {
    return checkUser;
  }

  if (!checkUser.isMember) {
    logger.warn(
      `User [${tokenDetails.userId}] is not a member of the organisation with ABN [${abn}], [{}]`,
      endpointEnrichLog()
    );

    return {
      success: false,
      error: {
        code: 403,
        message: "Forbidden: User is not a member of the organisation",
      },
    };
  }

  return checkUser;
}

/**
 * Validate the required scopes are included and user/org relationship
 * @param {TokenDetails} tokenDetails - The incoming OAuth access token details
 * @param {string} deviceId - The device id
 * @returns {PolicyResult}
 */
function userDeviceRelationshipPolicy(tokenDetails, deviceId) {
  // Check if the access token is with the required scopes
  if (!validateScope(tokenDetails.manageDeviceScopes, tokenDetails.scopes)) {
    logger.warn(
      `Missing required scope [${tokenDetails.manageDeviceScopes}] in the scopes [${tokenDetails.scopes}], [{}]`,
      endpointEnrichLog()
    );

    return {
      success: false,
      error: {
        code: 403,
        message: "Forbidden: Missing required scope",
      },
    };
  }

  // Query the user to ensure they exist
  const user = openidm.read(
    `${userManagedObjectKey}/${tokenDetails.userId}`,
    null,
    ["custom_memberOfDpOrg"]
  );

  if (!user) {
    return {
      success: false,
      error: {
        code: 404,
        message: `User not found: [${tokenDetails.userId}]`,
      },
    };
  }

  // Check is the user is a member of the organisation based on the deviceId
  const checkUser = checkUserDeviceMembership(deviceId, user);

  if (!checkUser.success) {
    return checkUser;
  }

  if (!checkUser.isMember) {
    logger.warn(
      `User [${tokenDetails.userId}] is not a member of the organisation who own the device [${deviceId}], [{}]`,
      endpointEnrichLog()
    );

    return {
      success: false,
      error: {
        code: 403,
        message: "Forbidden: User is not a member of the organisation",
      },
    };
  }

  return checkUser;
}

// TODO https://jira.apps.ndis.gov.au/browse/CIAFIN-6657
/**
 * Validate the required scopes are included and user/org relationship
 * @param {TokenDetails} tokenDetails - The incoming OAuth access token details
 * @param {string} certificateId - The certificate id
 * @returns {PolicyResult}
 */
function userCertificateRelationshipPolicy(tokenDetails, certificateId) {
  // Check if the access token is with the required scopes
  if (
    !validateScope(tokenDetails.manageCertificateScopes, tokenDetails.scopes)
  ) {
    logger.warn(
      `Missing required scope [${tokenDetails.manageCertificateScopes}] in the scopes [${tokenDetails.scopes}], [{}]`,
      endpointEnrichLog()
    );

    return {
      success: false,
      error: {
        code: 403,
        message: "Forbidden: Missing required scope",
      },
    };
  }

  // Query the user to ensure they exist
  const user = openidm.read(
    `${userManagedObjectKey}/${tokenDetails.userId}`,
    null,
    ["custom_memberOfDpOrg"]
  );

  if (!user) {
    return {
      success: false,
      error: {
        code: 404,
        message: `User not found: [${tokenDetails.userId}]`,
      },
    };
  }

  // Check is the user is a member of the organisation based on the certificateId
  const checkUser = checkUserCertificateMembership(certificateId, user);

  if (!checkUser.success) {
    return checkUser;
  }

  if (!checkUser.isMember) {
    logger.warn(
      `User [${tokenDetails.userId}] is not a member of the organisation who own the certificate [${certificateId}], [{}]`,
      endpointEnrichLog()
    );

    return {
      success: false,
      error: {
        code: 403,
        message: "Forbidden: User is not a member of the organisation",
      },
    };
  }

  return checkUser;
}

/**
 * @param {RequestContext} requestContext
 * @returns {PolicyResult}
 */
function registerDevicePolicy(requestContext) {
  const abn = requestContext.body["abn"];

  // Get details from the incoming access token
  const tokenDetails = retrieveTokenDetails();

  // Check user and org relationship
  const checkPolicy = userOrgRelationshipPolicy(tokenDetails, abn);

  if (!checkPolicy.success) {
    logger.warn(
      `User is not authorized to register device: [${checkPolicy.error.message}], [{}]`,
      endpointEnrichLog()
    );
  }
  return checkPolicy;
}

/**
 * Performs the operation to register a device.
 *
 * @param {RequestContext} requestContext
 * @returns {{ device: Device }}
 */
function registerDevice(requestContext) {
  const {
    abn,
    name: deviceName,
    environment: deviceEnvironment,
    type: deviceType,
    aggregatorAbn: aggregatorAbn,
  } = requestContext.body;

  // First check to see if there is an org with the supplied ABN in IDM - if not
  // just fail and do not create device

  const idmOrganisationAbnQuery = openidm.query(
    dpOrgManagedObjectKey,
    {
      _queryFilter: `abn eq "${abn}" and (type eq "provider" or type eq "providerViaAggregator")`,
    },
    ["*", "providers"]
  );

  if (
    !idmOrganisationAbnQuery.resultCount ||
    idmOrganisationAbnQuery.resultCount === 0
  ) {
    const missingOrgErrorMessage = `No digital partner organisation with ABN [${abn}] found`;
    logger.warn(`${missingOrgErrorMessage} [{}]`, endpointEnrichLog());
    throw {
      code: 404,
      message: missingOrgErrorMessage,
    };
  }

  if (idmOrganisationAbnQuery.resultCount > 1) {
    const duplicateOrgErrorMessage = `Multiple provider digital partner organisations with ABN [${abn}] found`;
    logger.error(`${duplicateOrgErrorMessage} [{}]`, endpointEnrichLog());
    throw {
      code: 500,
      message: duplicateOrgErrorMessage,
    };
  }
  const orgResults = idmOrganisationAbnQuery.result[0];
  /** @type {DeviceCreation} */
  const creationPayload = {
    name: deviceName,
    environment: deviceEnvironment,
    type: deviceType,
    abn: abn,
    // A device will always be created in an inactive state until 'activated'
    status: "inactive",
    organisation: {
      _ref: `${dpOrgManagedObjectKey}/${orgResults._id}`,
    },
  };
  if (aggregatorAbn) {
    // Device is an aggregator
    const idmOrganisationAggregatorAbnQuery = openidm.query(
      dpOrgManagedObjectKey,
      {
        _queryFilter: `abn eq "${aggregatorAbn}"`,
      },
      ["*"]
    );

    const aggregatorOrgResults = idmOrganisationAggregatorAbnQuery.result[0];
    creationPayload.aggregator = {
      _ref: `${dpOrgManagedObjectKey}/${aggregatorOrgResults._id}`,
    };
  }

  // Creation of the device in IDM. - validation checking done at request level,
  // this should always succeed
  const deviceIdmCreation = openidm.create(
    deviceManagedObjectKey,
    null,
    creationPayload
  );
  return {
    device: deviceIdmCreation,
  };
}
/**
 * Re-usable function to create the certificate managed object
 *
 * @param {object} certificatePayload - Object containing clientid, cert, serialnumber, expirydate, certstatus & relationship to device
 */
function certificateCreation(certificatePayload) {
  try {
    return openidm.create(`${certificateObjectKey}`, null, certificatePayload);
  } catch (error) {
    logger.error(
      `Failed to create certificate managed object: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Failed to create certificate managed object",
    };
  }
}

/**
 * @param {Device} device - device managed object
 * @param {string} cert - PEM certificate
 * @param {string} expiryDate - Expiry date of cert
 * @param {string} serialNumber - Serial number of cert
 */
function createDeviceOauthClientCallback(
  device,
  cert,
  expiryDate,
  serialNumber
) {
  // const oauthClientConfig = deviceOauthClient(device, cert);
  const oauthClientId = java.util.UUID.randomUUID().toString();

  const certificateCreationPayload = {
    oauthClientId: oauthClientId,
    certificate: cert,
    serialNumber: serialNumber,
    certificateExpiry: expiryDate,
    certificateStatus: "active",
    device: {
      _ref: `${deviceManagedObjectKey}/${device._id}`,
    },
  };
  try {
    logger.info(`Creating Certificate Object, [{}]`, endpointEnrichLog());
    const certificateManagedObject = certificateCreation(
      certificateCreationPayload
    );
    logger.info(
      `Certificate Object has been created successfully for client ${oauthClientId}, [{}]`,
      endpointEnrichLog()
    );
    return {
      oauthClient: oauthClientId,
      certificate: certificateManagedObject,
    };
  } catch (error) {
    logger.error(
      `Unexpectedly failed to create new certificate managed object for device [${device.name
      }] and clientId [${certificateCreationPayload.oauthClientId
      }]: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Unexpectedly failed to create new certificate managed object",
      detail: {
        name: device.name,
        ciamId: certificateCreationPayload.oauthClientId,
      },
    };
  }
}

/**
 * Exchanges a CSR for a certificate from the PKI service.
 *
 * @param {string} templateId - The PKI template ID
 * @param {string} caId - The PKI CA ID
 * @param {string} pkiEndpoint - The PKI service endpoint URL
 * @param {string} pkiToken - The PKI service token for authentication
 * @param {string} csr - The Certificate Signing Request (CSR) in PEM format
 */
function exchangeCsrForCert(templateId, caId, pkiEndpoint, pkiToken, csr) {
  try {
    const pkiResponse = openidm.action("external/rest", "call", {
      url: pkiEndpoint,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Jellyfish-Token": pkiToken,
      },
      body: JSON.stringify({
        template_id: templateId,
        ca_id: caId,
        csr: csr,
      }),
    });
    if (
      !pkiResponse ||
      typeof pkiResponse.cert !== "string" ||
      !pkiResponse.cert.includes("-----BEGIN CERTIFICATE-----")
    ) {
      logger.error(
        "PKI certificate request is missing expected content [{}]",
        endpointEnrichLog({
          pkiResponse: pkiResponse,
          templateId: templateId,
          caId: caId,
        })
      );
    }
    return pkiResponse;
  } catch (error) {
    logger.error(
      `Error occurred while obtaining certificate from PKI service: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Failed to obtain certificate from PKI service",
    };
  }
}

/**
 * Activates the device on Mulesoft for upstream services to consume.
 *
 * @param {string} mulesoftDomain - The base URL for the Mulesoft API
 * @param {Object} mulesoftCredentials - The credentials for Mulesoft API access
 * @param {string} orgNdisNumber - The NDIS number of the PACE organisation
 * @param {string} deviceCiamId - The CIAM ID of the device to
 * @param {string} deviceName - The name of the device to activate
 */
function activateMulesoftDevice(
  mulesoftDomain,
  mulesoftCredentials,
  orgNdisNumber,
  deviceCiamId,
  deviceName
) {
  try {
    logger.info(
      `Activating device in Mulesoft for org [${orgNdisNumber}] and device CIAM ID [${deviceCiamId}], [{}]`,
      endpointEnrichLog()
    );
    const mulesoftDeviceEndpoint = `${mulesoftDomain}/providers/${orgNdisNumber}/devices/${deviceCiamId}`;

    const mulesoftResponse = openidm.action("external/rest", "call", {
      url: mulesoftDeviceEndpoint,
      method: "POST",
      headers: Object.assign({}, mulesoftCredentials, {
        "Content-Type": "application/json",
      }),
      body: JSON.stringify({
        device_name: deviceName,
      }),
    });
    logger.info(
      `Successfully activated device [${deviceCiamId}] in Mulesoft:  [{}]`,
      endpointEnrichLog({
        mulesoftResponse: JSON.stringify(mulesoftResponse),
      })
    );
    return mulesoftResponse;
  } catch (error) {
    logger.error(
      `Error occurred while activating device in Mulesoft: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Failed to activate device in Mulesoft",
    };
  }
}

/**
 * Deletes the device in Mulesoft for upstream services to consume.
 *
 * @param {string} mulesoftDomain - The base URL for the Mulesoft API
 * @param {Object} mulesoftCredentials - The credentials for Mulesoft API access
 * @param {string} orgNdisNumber - The NDIS number of the PACE organisation
 * @param {string} deviceCiamId - The CIAM ID of the device to
 * @param {string} deviceName - The name of the device to activate
 */
function deleteMulesoftDevice(
  mulesoftDomain,
  mulesoftCredentials,
  orgNdisNumber,
  deviceCiamId,
  deviceName
) {
  try {
    logger.info(
      `Deleting device in Mulesoft for org [${orgNdisNumber}] and device CIAM ID [${deviceCiamId}], [{}]`,
      endpointEnrichLog()
    );
    //note - may need to %% spaces for deviceName
    const encodeDeviceName = deviceName.replace(/ /g, "%");
    const mulesoftDeleteDeviceEndpoint = `${mulesoftDomain}/providers/${orgNdisNumber}/devices/${deviceCiamId}?device_name=${encodeDeviceName}`;

    const mulesoftResponse = openidm.action("external/rest", "call", {
      url: mulesoftDeleteDeviceEndpoint,
      method: "DELETE",
      headers: Object.assign({}, mulesoftCredentials, {
        "Content-Type": "application/json",
      }),
    });
    logger.info(
      `Successfully deleted device [${deviceCiamId}] in Mulesoft:  [{}]`,
      endpointEnrichLog({
        mulesoftResponse: JSON.stringify(mulesoftResponse),
      })
    );
    return mulesoftResponse;
  } catch (error) {
    logger.error(
      `Error occurred while deleting device in Mulesoft: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Failed to delete device in Mulesoft",
    };
  }
}

/**
 * Get the Org NDIS Number from the PACE org
 *
 * @param {DpOrganisation} org
 * @param {"test" | "prod"} vendorEnv
 * @returns {string}
 */
function getOrgNdisNumber(org, vendorEnv) {
  const dpOrgAbn = org.abn;
  const alphaOrgsRes = openidm.query(
    "managed/alpha_organization",
    {
      _queryFilter: `/custom_ABN eq "${dpOrgAbn}" and !(/custom_ignore eq true)`,
    },
    ["custom_NDISNumber"]
  );
  const alphaOrgs = (alphaOrgsRes && alphaOrgsRes.result) || [];
  if (alphaOrgs.length === 0) {
    throw {
      code: 404,
      message: `No alpha_organization found with ABN: [${dpOrgAbn}]`,
    };
  }

  // We allow duplicate orgs, we just need to ensure at least one is active
  if (alphaOrgs.length > 1) {
    logger.warn(
      `Multiple alpha_organization found with ABN: [${dpOrgAbn}], [{}]`,
      endpointEnrichLog()
    );
  }

  const alphaOrg = alphaOrgs[0];

  // When the vendor env is production, we can use the real PACE-synced NDIS
  // number
  if (vendorEnv === "prod") {
    return alphaOrg.custom_NDISNumber;
  }

  // Otherwise, we need to get it from the provider DP org
  const vendorTestOrgNdisNumber = org.vendorTestOrgNdisNumber;
  if (!vendorTestOrgNdisNumber) {
    throw {
      code: 400,
      message: `No Vendor Test org NDIS number found for provider DP org with ABN: [${dpOrgAbn}]`,
    };
  }
  return vendorTestOrgNdisNumber;
}

/**
 * Parses a PEM encoded certificate to pull out the expiry date
 *
 * @param {string} cert - The PEM certificate recieved from PKI
 */
function parseCertificate(cert) {
  try {
    const String = javaImports.String;
    const ByteArrayInputStream = javaImports.ByteArrayInputStream;
    const CertificateFactory = javaImports.CertificateFactory;
    const SimpleDateFormat = javaImports.SimpleDateFormat;

    const pemBytes = new String(cert).getBytes("UTF-8");
    const inputStream = new ByteArrayInputStream(pemBytes);
    const certFactory = CertificateFactory.getInstance("X.509");
    const certificate = certFactory.generateCertificate(inputStream);

    const expiry = certificate.getNotAfter();
    const sdf = new SimpleDateFormat("yyyy-MM-dd");
    const expiryDateStr = sdf.format(expiry);

    return expiryDateStr;
  } catch (error) {
    logger.error(
      `Failed to parse certificate: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 400,
      message: "Certificate format invalid. Failed to parse.",
    };
  }
}

/**
 * @param {RequestContext} requestContext
 * @returns {PolicyResult}
 */
function addCertPolicy(requestContext) {
  const deviceId = requestContext.body["deviceId"];
  // Get details from the incoming access token
  const tokenDetails = retrieveTokenDetails();

  // Check user and certificate relationship
  const checkPolicy = userDeviceRelationshipPolicy(tokenDetails, deviceId);

  if (!checkPolicy.success) {
    logger.warn(
      `User is not authorized to add cert for device [${deviceId
      }]: [${checkPolicy.error.message}], [{}]`,
      endpointEnrichLog()
    );
  }
  return checkPolicy;
}

/**
 * Performs the operation to renew a device.
 *
 * @param {RequestContext} requestContext
 * @returns the output for the caller
 */
function addCert(requestContext) {
  const config = retrieveConfig();

  const csr = requestContext.body["csr"];
  const deviceId = requestContext.body["deviceId"];

  const cert = exchangeCsrForCert(
    config.pkiTemplateId,
    config.pkiCaId,
    config.pkiEndpoint,
    config.pkiToken,
    csr
  );

  const expiryDate = parseCertificate(cert.cert);

  logger.info(
    "Successfully exchanged CSR for cert with PKI service, [{}]",
    endpointEnrichLog()
  );
  const deviceManagedObject = /** @type {Device} */ (
    openidm.read(`${deviceManagedObjectKey}/${deviceId}`, null, [
      "*",
      "organisation/*",
      "certificates/*",
    ])
  );
  if (!deviceManagedObject) {
    logger.error(
      "Device with ID [{}] not found in IDM [{}]",
      deviceId,
      endpointEnrichLog()
    );
    throw {
      code: 404,
      message: "Device not found",
      detail:
        "Ensure the deviceId provided is the IDM UUID '_id', not the 'ciamId'",
    };
  }
  if (
    !deviceManagedObject.organisation ||
    (String(deviceManagedObject.organisation.type).toLowerCase() !==
      "provider" &&
      String(deviceManagedObject.organisation.type).toLowerCase() !==
      "providerViaAggregator")
  ) {
    logger.error(
      "Device with ID [{}] is not associated with a provider organisation [{}]",
      deviceId,
      endpointEnrichLog({
        deviceManagedObject: deviceManagedObject,
      })
    );
    throw {
      code: 400,
      message: "Device must be associated with a provider organisation",
    };
  }
  const orgNdisNumber = getOrgNdisNumber(
    deviceManagedObject.organisation,
    deviceManagedObject.environment
  );
  if (!orgNdisNumber) {
    logger.error(
      "The org for the device has no NDIS number [{}]",
      endpointEnrichLog({
        deviceOrganisation: deviceManagedObject.organisation,
      })
    );
    throw {
      code: 400,
      message: `Device has no matching NDIS org with ABN [${deviceManagedObject.organisation.abn}]`,
    };
  }

  const oauthClientDetails = createDeviceOauthClientCallback(
    deviceManagedObject,
    cert.cert,
    expiryDate,
    cert.serialnumber
  );
  const clientId = oauthClientDetails.oauthClient;

  return {
    oauthClientId: clientId,
    device: {
      name: deviceManagedObject.name,
      ciamId: deviceManagedObject.ciamId,
      type: deviceManagedObject.type,
      environment: deviceManagedObject.environment,
      deviceId: deviceId,
    },
    certificate: {
      cert: cert.cert,
    },
  };
}

/**
 * @param {RequestContext} _requestContext
 * @returns {PolicyResult}
 */
function revokeCertPolicy(_requestContext) {
  // TODO https://jira.apps.ndis.gov.au/browse/CIAFIN-6657
  return { success: true };
}

/**
 * Performs the operation to revoke a device.
 *
 * @param {RequestContext} requestContext
 * @returns the output for the caller
 */
function revokeCert(requestContext) {
  const config = retrieveConfig();
  const oauthClientId = requestContext.body["oauthClientId"];
  const queryCertificateData = openidm.query(`${certificateObjectKey}`, {
    _queryFilter: `oauthClientId eq "${oauthClientId}"`,
  });
  const certificateQueryResult = queryCertificateData.result[0];
  const serialNumber = certificateQueryResult.serialNumber;
  const certificateId = certificateQueryResult._id;

  try {
    logger.info(
      `Updating certificateStatus for clientId [${oauthClientId}] to revoked, [{}]`,
      endpointEnrichLog()
    );
    openidm.patch(`${certificateObjectKey}/${certificateId}`, null, [
      {
        operation: "replace",
        field: "certificateStatus",
        value: "revoked",
      },
    ]);
    logger.info(
      `Successfully updated certificateStatus to revoked for clientId [${oauthClientId}], [{}]`,
      endpointEnrichLog()
    );
  } catch (error) {
    logger.error(
      `Failed to update certificateStatus to revoked for clientId [${certificateQueryResult.oauthClientId
      }]: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message:
        "Certificate update failed. Please ensure that you have provided the correct information.",
      detail: {
        clientId: certificateQueryResult.oauthClientId,
      },
    };
  }
  try {
    logger.info(
      `Contacting PKI server to revoke certificate with serial number [${serialNumber}], [{}]`,
      endpointEnrichLog()
    );
    openidm.action("external/rest", "call", {
      url: config.pkiRevokeEndpoint,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Jellyfish-Token": config.pkiToken,
      },
      body: JSON.stringify({
        caname: config.caName,
        serial: serialNumber,
        reason: certOperationReasons.cessationOfOperation, //cessation of operation
      }),
    });
    logger.info(
      `Successfully revoked certificate with serial number [${serialNumber}] at PKI server, [{}]`,
      endpointEnrichLog()
    );
  } catch (error) {
    logger.error(
      `Failed to revoke certificate at PKI server for clientId [${certificateQueryResult.oauthClientId
      }]: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Unexpectedly failed to revoke device.",
      detail: {
        oauthClientId: certificateQueryResult.oauthClientId,
      },
    };
  }
  return {
    code: 200,
    message: `Successfully revoked device certificate associated with the Client Id ${oauthClientId}`,
  };
}

/**
 * @param {RequestContext} _requestContext
 * @returns {PolicyResult}
 */
function deleteDevicePolicy(_requestContext) {
  // TODO https://jira.apps.ndis.gov.au/browse/CIAFIN-6657
  return { success: true };
}

/**
 * Performs the operation to delete a device
 *
 * @param {RequestContext} requestContext
 * @returns the output for the caller
 */
function deleteDevice(requestContext) {
  const config = retrieveConfig();

  const deviceManagedObject = /** @type {Device} */ (
    openidm.read(
      `${deviceManagedObjectKey}/${requestContext.body["deviceId"]}`,
      null,
      ["*", "organisation/*", "certificates"]
    )
  );
  const certificateIdsToDelete = extractRefIdsFromArrayField(
    [deviceManagedObject],
    "certificates"
  );
  /*
  const deviceVendorEnv = deviceManagedObject.environment;
  const orgNdisNumber = getOrgNdisNumber(
    deviceManagedObject.organisation,
    deviceVendorEnv
  );
  if (!orgNdisNumber) {
    logger.error(
      "The org for the device has no NDIS number [{}]",
      endpointEnrichLog({
        deviceOrganisation: deviceManagedObject.organisation,
      })
    );
    throw {
      code: 400,
      message: `Device has no matching NDIS org with ABN [${deviceManagedObject.organisation.abn}]`,
    };
  }

  const isMulesoftIntegrationEnabledForDeletion =
    (deviceVendorEnv === "prod" &&
      config.vendorProdIsMulesoftIntegrationEnabled) ||
    (deviceVendorEnv === "test" &&
      config.vendorTestIsMulesoftIntegrationEnabled);
  if (isMulesoftIntegrationEnabledForDeletion) {
    deleteMulesoftDevice(
      deviceVendorEnv === "prod"
        ? config.vendorProdMulesoftDomain
        : config.vendorTestMulesoftDomain,
      deviceVendorEnv === "prod"
        ? config.vendorProdMulesoftCredentials
        : config.vendorTestMulesoftCredentials,
      orgNdisNumber,
      deviceManagedObject.ciamId,
      deviceManagedObject.name
    );
  } else {
    logger.info(
      `Mulesoft integration is disabled in vendor [${deviceVendorEnv}] environment, skipping device deletion [{}]`,
      endpointEnrichLog()
    );
  }

  logger.info(
    `Certificate Ids: ${JSON.stringify(certificateIdsToDelete)} [{}]`,
    endpointEnrichLog()
  );

  for (var i = 0; i < certificateIdsToDelete.length; i++) {
    var certificateId = certificateIdsToDelete[i];
    logger.info(
      `Deleting Certificate with Id: ${certificateId} [{}]`,
      endpointEnrichLog()
    );
    openidm.delete(`${certificateObjectKey}/${certificateId}`, null);
    logger.info(`Deleted ID  ${certificateId} [{}]`, endpointEnrichLog());
  }
  logger.info(
    `Deleting Device with Id: ${requestContext.body["deviceId"]} [{}]`,
    endpointEnrichLog()
  );
  */
  const deleteSelf = openidm.delete(
    `${deviceManagedObjectKey}/${requestContext.body["deviceId"]}`,
    null
  );
  logger.info(
    `Successfully deleted Device With ID: ${requestContext.body["deviceId"]} [{}]`,
    endpointEnrichLog()
  );

  return { deleteSelf };
}

/**
 * @param {RequestContext} _requestContext
 * @returns {PolicyResult}
 */
function registerActivatePolicy(_requestContext) {
  // TODO https://jira.apps.ndis.gov.au/browse/CIAFIN-6657
  return { success: true };
}

/**
 * Performs the operation to register & activate a device.
 *
 * @param {RequestContext} requestContext
 * @returns the output for the caller
 */
function registerActivate(requestContext) {
  var deviceId;
  try {
    const deviceRegister = registerDevice(requestContext);
    logger.info("Successfully registered device [{}]", endpointEnrichLog());
    deviceId = deviceRegister.device._id;

    const csr = extractActivationDeviceFields(requestContext).csr;

    try {
      const activation = activateDevice(csr, deviceId);
      logger.info("Successfully activated device [{}]", endpointEnrichLog());
      return activation;
    } catch (activationError) {
      logger.error(
        `Failed to activate device with ID [${deviceId}] with error [${activationError.toString()}], [{}]`,
        endpointEnrichLog()
      );
      // Cleanup since activation failed
      try {
        openidm.delete(`${deviceManagedObjectKey}/${deviceId}`, null);
      } catch (deletionError) {
        logger.error(
          `Failed to delete device with ID [${deviceId}] after activation failure: [${deletionError.toString()}], [{}]`,
          endpointEnrichLog()
        );
      }
      throw {
        code: 500,
        message: "Failed to activate the device",
        details: activationError,
      };
    }
  } catch (error) {
    if (!deviceId) {
      // Registration failed, no deviceId to cleanup
      logger.error(
        `Failed to register device: [${error.toString()}], [{}]`,
        endpointEnrichLog()
      );
    }
    throw {
      code: 500,
      message: "Failed to register and activate device",
      details: error.message || error,
    };
  }
}
/**
 * Retrieves the necessary fields to activate a device - this was needed to support register + activate case
 *
 * @param {RequestContext} requestContext
 * @returns the request body fields to be used for device activation
 */
function extractActivationDeviceFields(requestContext) {
  const csr = requestContext.body["csr"];
  const deviceId = requestContext.body["deviceId"];
  return {
    csr,
    deviceId,
  };
}
/**
 * Helper function that will just return a configureable date (ESV) that is used to set deviceExpiry (currently set as 24 months).
 *
 * @returns the output for the caller
 */
function deviceExpiry(expiryMonths) {
  const now = new javaImports.Date();
  const calendar = javaImports.Calendar.getInstance();
  calendar.setTime(now);
  calendar.add(javaImports.Calendar.MONTH, expiryMonths);

  const deviceExpiryDate = calendar.getTime();

  const sdf = new javaImports.SimpleDateFormat("yyyy-MM-dd");
  const deviceExpiryFormatted = sdf.format(deviceExpiryDate);
  return deviceExpiryFormatted;
}
/**
 * This function helps extract referenceIds out of an Openidm.query
 * @param {Array<object>} objects Array of objects (result of an openIdm.query)
 * @param {string}  fieldName  the fieldname you want to query referenceIds out of e.g "Certificates"
 *
 * @returns {Array<string>} Array of reference resource Ids extracted from specified field
 */
function extractRefIdsFromArrayField(objects, fieldName) {
  var ids = [];

  for (var i = 0; i < objects.length; i++) {
    var item = objects[i];
    var refs = item[fieldName] || [];

    for (var j = 0; j < refs.length; j++) {
      var ref = refs[j];
      if (ref && ref._refResourceId) {
        ids.push(ref._refResourceId);
      }
    }
  }
  return ids;
}

/**
 * This function helps extract referenceIds out of an Openidm.query when the referenceIds are within an object
 * @param {object} objects - Objects is an object
 * @param {string}  fieldName  the fieldname you want to query referenceIds out of e.g "Organisation"
 *
 * @returns {Array<string>} Array of reference resource Ids extracted from specified field
 */
function extractRefIdsFromObjectField(objects, fieldName) {
  var ids = [];

  for (var i = 0; i < objects.length; i++) {
    var item = objects[i];
    var ref = item[fieldName] || [];

    if (ref && ref._refResourceId) {
      if (ids.indexOf(ref._refResourceId) === -1) {
        ids.push(ref._refResourceId);
      }
    }
  }
  return ids;
}

/**
 * This function helps form the _queryFilter to perform a batch request of multiple Id's.
 * It is used when the referenceId's are within a
 * @param {Array<object>} refs - Array of reference objects containing _refResourceId properties
 *
 * @returns {string} Query filter string in format "_id eq 'id1' or _id eq 'id2' or ...."
 */
function queryIdFilter(refs) {
  return refs
    .filter((ref) => ref && ref._refResourceId)
    .map((ref) => `/_id eq "${ref._refResourceId}"`)
    .join(" or ");
}

/**
 * This function helps form the _queryFilter on an Array of strings
 * @param {Array<object>} ids - Array of strings  containing _refResourceId properties
 *
 * @returns {string} Query filter string in format "_id eq 'id1' or _id eq 'id2' or ...."
 */
function queryIdFilterFromIds(ids) {
  return ids.map((id) => `_id eq "${id}"`).join(" or  ");
}

/**
 * @typedef {Record<string, {name: string, type: string, abn?: string}>} MapOrganisationData
 */

/**
 * This function is used to form the result of an openIDM query on the organisation managed object.
 * The result of this function is used to display details of the Provider org or Aggregator org
 * @param {Array<object>} orgData  Result from an OpenIdm Query
 *
 * @returns {MapOrganisationData} Organisational data
 */
function mapOrganisationData(orgData) {
  /** @type {MapOrganisationData} */
  var orgMap = {};
  for (var i = 0; i < orgData.length; i++) {
    var org = orgData[i];
    var orgObj = {
      name: org.name,
      type: org.type,
    };
    if (org.abn) {
      orgObj.abn = org.abn;
    }
    orgMap[org._id] = orgObj;
  }
  return orgMap;
}

/**
 * @typedef {{
 * devices: {
 *   certificates: {
 *     certificateStatus: string;
 *     certificateExpiry: string;
 *     oauthClientId: string;
 *   }[];
 *   deviceName: string;
 *   deviceId: string
 *   deviceStatus?: string;
 *   provider?: { name: string; type: string };
 *   aggregator?: { name: string; type: string };
 * }[];
 * organisation?: {
 *   name: string;
 *   abn?: string;
 *   type: string;
 * };
 * }} GetDeviceListRes
 */

/**
 * @param {RequestContext} _requestContext
 * @returns {PolicyResult}
 */
function getDeviceListPolicy(_requestContext) {
  // TODO https://jira.apps.ndis.gov.au/browse/CIAFIN-6657
  return { success: true };
}

// TODO cleanup the logic here by extracting into smaller functions for readability
/**
 * Performs the operation to retrieve information about an org, their registered devices & details about the certificate.
 *
 * @param {RequestContext} requestContext
 * @returns {GetDeviceListRes}
 */
function getDeviceList(requestContext) {
  //Openidm.query is more flexible as we can use it to reference any of the fields - using openidm.read returns as a JSON response which is easier but Registration portal would need some way to know that _id.
  const queryOrganisationData = openidm.query(
    `${dpOrgManagedObjectKey}`,
    {
      _queryFilter: `abn eq "${requestContext.query["abn"]}"`,
    },
    ["_id", "name", "abn", "type", "devices", "providerDevices"]
  );
  logger.info(
    "Successfully identified organisation, [{}]",
    endpointEnrichLog()
  );
  if (
    !queryOrganisationData ||
    !queryOrganisationData.result ||
    queryOrganisationData.result.length === 0
  ) {
    throw {
      code: 404,
      message: `Organisation with an abn: ${requestContext.query["abn"]} not found`,
    };
  }
  //returns as an array
  const organisation = queryOrganisationData.result[0];
  const provider_types = ["provider", "direct integrator"];
  const aggregator_types = ["aggregator", "providerviaAggregator"];
  const isProvider = provider_types.includes(organisation.type);
  const isAggregator = aggregator_types.includes(organisation.type);
  const filterDevices = queryIdFilter(organisation.devices);
  const filterProviderAggregator = queryIdFilter(organisation.providerDevices);

  if (!isProvider && !isAggregator) {
    throw {
      code: 500,
      message: "Organisation type is incorrect",
    };
  }

  try {
    /** @type {{result: Device[]}} */
    var resolvedDevices = {
      result: [],
    };
    /** @type {{result: Device[]}} */
    var resolvedProviderDevices = {
      result: [],
    };
    var resolvedCerts = [];

    if (isProvider) {
      try {
        logger.info(
          `Querying provider devices for org: [${requestContext.query["abn"]}], [{}]`,
          endpointEnrichLog()
        );
        resolvedDevices = openidm.query(
          `${deviceManagedObjectKey}`,
          {
            _queryFilter: filterDevices,
          },
          [
            "name",
            "type",
            "certificates",
            "status",
            "providerDevice",
            "organisation",
            "aggregator",
          ]
        );
        logger.info(
          `Successfully queried provider devices for org: [${requestContext.query["abn"]}], [{}]`,
          endpointEnrichLog()
        );
        if (!resolvedDevices || !resolvedDevices.result) {
          resolvedDevices = {
            result: [],
          };
          logger.info(
            `Provider Organisation does not have any identified provider devices: [${requestContext.query["abn"]}], [{}]`,
            endpointEnrichLog()
          );
        }
      } catch (error) {
        logger.error(
          `Error while querying provider organisation: [${requestContext.query["abn"]}] for provider devices, setting provider device list [${error.String()}], [{}]`,
          endpointEnrichLog()
        );
        resolvedDevices = {
          result: [],
        };
      }
      try {
        logger.info(
          `"Querying aggregator devices for org: [${requestContext.query["abn"]}]", [{}]`,
          endpointEnrichLog()
        );
        resolvedProviderDevices = openidm.query(
          `${deviceManagedObjectKey}`,
          {
            _queryFilter: filterProviderAggregator,
          },
          [
            "name",
            "type",
            "certificates",
            "status",
            "providerDevice",
            "organisation",
            "aggregator",
          ]
        );
        logger.info(
          `Successfully queried aggregator devices for org: [${requestContext.query["abn"]}], [{}]`,
          endpointEnrichLog()
        );
        if (!resolvedProviderDevices || !resolvedProviderDevices.result) {
          resolvedProviderDevices = {
            result: [],
          };
          logger.info(
            `Provider Organisation does not have any identified aggregator devices: [${requestContext.query["abn"]}], [{}]`,
            endpointEnrichLog()
          );
        }
      } catch (error) {
        logger.error(
          `Error while querying provider organisation: [${requestContext.query["abn"]}] for aggregator devices, setting aggregator device list [${error.toString()}], [{}]`,

          endpointEnrichLog()
        );
        resolvedProviderDevices = {
          result: [],
        };
      }
    } else if (isAggregator) {
      try {
        logger.info(
          `"Querying aggregator devices for org: ${requestContext.query["abn"]}"`,
          endpointEnrichLog()
        );
        resolvedProviderDevices = openidm.query(
          `${deviceManagedObjectKey}`,
          {
            _queryFilter: filterProviderAggregator,
          },
          [
            "name",
            "type",
            "certificates",
            "status",
            "providerDevice",
            "organisation",
            "aggregator",
          ]
        );
        logger.info(
          `Successfully queried aggregator devices for org: [${requestContext.query["abn"]}], [{}]`,
          endpointEnrichLog()
        );

        if (!resolvedProviderDevices || !resolvedProviderDevices.result) {
          resolvedProviderDevices = {
            result: [],
          };
          logger.info(
            `Aggregator Organisation does not have any identified aggregator devices: [${requestContext.query["abn"]}], [{}]`,
            endpointEnrichLog()
          );
        }
      } catch (error) {
        logger.error(
          `Error while querying aggregator organisation: ${requestContext.query["abn"]} for aggregator devices, setting device list [${error.toString()}, [{}]`,
          endpointEnrichLog()
        );
        resolvedProviderDevices = {
          result: [],
        };
      }
    }

    const allDevices = (resolvedDevices.result || []).concat(
      resolvedProviderDevices.result || []
    );

    if (allDevices.length === 0) {
      return {
        organisation: {
          name: organisation.name,
          type: organisation.type,
        },
        devices: [],
      };
    }
    const certIds =
      extractRefIdsFromArrayField(allDevices, "certificates") || [];

    if (certIds.length === 0) {
      return {
        organisation: {
          name: organisation.name,
          type: organisation.type,
        },
        devices: resolvedDevices.result.map((device) => ({
          deviceName: device.name,
          deviceStatus: device.status,
          certificates: [],
        })),
      };
    }
    const certFilter = certIds.map((id) => `/_id eq "${id}"`).join(" or ");
    logger.info(
      `Querying device certificates for ${certIds.length} for org: [${requestContext.query["abn"]}], [{}]`,
      endpointEnrichLog()
    );
    const resolvedCertificateQuery = openidm.query(
      `${certificateObjectKey}`,
      {
        _queryFilter: certFilter,
      },
      ["oauthClientId", "certificateExpiry", "certificateStatus", "_id"]
    );
    logger.info(
      `Queried certificates for org: [${requestContext.query["abn"]}], [{}]`,
      endpointEnrichLog()
    );

    resolvedCerts = resolvedCertificateQuery.result || [];

    var certMap = {};
    resolvedCerts.forEach((cert) => {
      certMap[cert._id] = cert;
    });

    var providerOrgRefs = extractRefIdsFromObjectField(
      allDevices,
      "organisation"
    );
    var aggregatorOrgRefs = extractRefIdsFromObjectField(
      allDevices,
      "aggregator"
    );

    if (providerOrgRefs.length > 0) {
      var providerOrgFilter = queryIdFilterFromIds(providerOrgRefs);
      try {
        logger.info(
          `Querying reference Id's to provider Organisations`,
          endpointEnrichLog()
        );
        var providerOrgs = openidm.query(
          `${dpOrgManagedObjectKey}`,
          {
            _queryFilter: providerOrgFilter,
          },
          ["name", "type"]
        );
        logger.info(
          `Successfully identified provider Organisations, [{}]`,
          endpointEnrichLog()
        );
      } catch (error) {
        logger.error(
          `Failed to query providerOrgs. Error: [${error.toString()}], [{}]`,
          endpointEnrichLog()
        );
        throw {
          code: 500,
          message: `Internal server error`,
        };
      }
      // TODO extract these try-catch statements into functions to simplify error handling and assign directly to a const
      /** @type {MapOrganisationData} */
      var providerOrgMap;
      try {
        const providerOrgResults = providerOrgs.result;
        providerOrgMap = mapOrganisationData(providerOrgResults);
        logger.info(
          `Successfully mapped provider Organisations, [{}]`,
          endpointEnrichLog()
        );
      } catch (error) {
        logger.error(
          `Failed to complete mapping of providerOrgs. Error: [${error.toString()}], [{}]`,
          endpointEnrichLog()
        );
        throw {
          code: 500,
          message: `Internal server error`,
        };
      }
    }

    if (aggregatorOrgRefs.length > 0) {
      var aggregatorOrgFilter = queryIdFilterFromIds(aggregatorOrgRefs);
      try {
        logger.info(
          `Querying reference Id's to aggregator Organisations`,
          endpointEnrichLog()
        );
        var aggregatorOrgs = openidm.query(
          `${dpOrgManagedObjectKey}`,
          {
            _queryFilter: aggregatorOrgFilter,
          },
          ["name", "type"]
        );
        logger.info(
          `Successfully identified aggregator Organisations, [{}]`,
          endpointEnrichLog()
        );
      } catch (error) {
        logger.error(
          `Failed to query aggregatorOrgs [${error.toString()}], [{}]`,
          endpointEnrichLog()
        );
        throw {
          code: 500,
          message: `Internal server error`,
        };
      }
      // TODO extract these try-catch statements into functions to simplify error handling and assign directly to a const
      /** @type {MapOrganisationData} */
      var aggregatorOrgMap;
      try {
        const aggregatorOrgsResults = aggregatorOrgs.result;
        aggregatorOrgMap = mapOrganisationData(aggregatorOrgsResults);
        logger.info(
          `Successfully mapped aggregator Organisations, [{}]`,
          endpointEnrichLog()
        );
      } catch (error) {
        logger.error(
          `Failed to complete mapping of aggregatorOrgs. Error: [${error.toString()}], [{}]`,
          endpointEnrichLog()
        );
        throw {
          code: 500,
          message: `Internal server error`,
        };
      }
    }
    try {
      /** @type {GetDeviceListRes["devices"]} */
      var resolvedfinal = allDevices.map((device) => {
        //Map Certificates first
        var resolvedCertsForDevice = (device.certificates || [])
          .map((certRef) => certMap[certRef._refResourceId])
          .filter(Boolean)
          .map(function (cert) {
            return {
              oauthClientId: cert.oauthClientId,
              certificateExpiry: cert.certificateExpiry,
              certificateStatus: cert.certificateStatus,
            };
          });
        //Get providerOrg info
        var providerOrgInfo = undefined;
        if (device.organisation && device.organisation._refResourceId) {
          providerOrgInfo =
            providerOrgMap[device.organisation._refResourceId] || undefined;
        }
        //Get aggregatorOrgInfo if it exists
        var aggregatorOrgInfo = undefined;
        if (device.aggregator && device.aggregator._refResourceId) {
          aggregatorOrgInfo =
            aggregatorOrgMap[device.aggregator._refResourceId] || undefined;
        }
        //Combine
        var result = {
          deviceName: device.name,
          deviceId: device._id,
          deviceStatus: device.status,
          certificates: resolvedCertsForDevice,
          provider: providerOrgInfo,
        };
        //Aggregator if it exists
        if (aggregatorOrgInfo) {
          result.aggregator = aggregatorOrgInfo;
        }
        return result;
      });
    } catch (error) {
      logger.error(
        `Failed while resolving devices. Error: [${error.toString()}], [{}]`,
        endpointEnrichLog()
      );
      throw {
        code: 500,
        message: "Internal server error",
      };
    }
    return {
      devices: resolvedfinal,
    };
  } catch (error) {
    logger.error(
      `Failed fetching device information, Error: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Error with fetching device information",
    };
  }
}

/**
 * @typedef {{
 * device: [{certificates:
 * [{certificateStatus: string, certificateExpiry: string, oauthClientId: string}]
 * deviceName: string,
 * deviceStatus: string,
 * deviceExpiry: string,
 * deviceEnvironment: string,
 * deviceType: string,
 * provider: {name: string, type: string, abn: string}
 * aggregator: {name: string, type: string, abn: string}}]
 * }} getDeviceDetail
 */

/**
 * @param {RequestContext} _requestContext
 * @returns {PolicyResult}
 */
function getDeviceDetailPolicy(_requestContext) {
  // TODO https://jira.apps.ndis.gov.au/browse/CIAFIN-6657
  return { success: true };
}

/**
 * Performs the operation to retrieve information about a device.
 *
 * @param {RequestContext} requestContext
 * @returns {getDeviceDetail}
 */
function getDeviceDetail(requestContext) {
  const queryDeviceData = openidm.query(
    `${deviceManagedObjectKey}`,
    {
      _queryFilter: `_id eq "${requestContext.query["deviceId"]}"`,
    },
    [
      "_id",
      "name",
      "environment",
      "type",
      "deviceExpiry",
      "status",
      "organisation",
      "aggregator",
      "certificates",
    ]
  );
  logger.info("Successfully identified device, [{}]", endpointEnrichLog());
  if (
    !queryDeviceData ||
    !queryDeviceData.result ||
    queryDeviceData.result.length === 0
  ) {
    throw {
      code: 404,
      message: `Device: ${requestContext.query["deviceId"]} was not found`,
    };
  }
  //returns as an array
  const deviceData = queryDeviceData.result;

  const certRefs =
    extractRefIdsFromArrayField(deviceData, "certificates") || [];
  const providerOrgRefs =
    extractRefIdsFromObjectField(deviceData, "organisation") || [];
  const aggregatorOrgRefs =
    extractRefIdsFromObjectField(deviceData, "aggregator") || [];

  const certFilter = certRefs.map((id) => `/_id eq "${id}"`).join(" or ");
  logger.info(
    `Querying device certificates for [${certRefs.length}] for device: [${requestContext.query["deviceId"]}], [{}]`,
    endpointEnrichLog()
  );
  const resolvedCertificateQuery = openidm.query(
    `${certificateObjectKey}`,
    {
      _queryFilter: certFilter,
    },
    ["certificateExpiry", "certificateStatus", "_id"]
  );
  logger.info(
    `Queried certificates for device: [${requestContext.query["deviceId"]}], [{}]`,
    endpointEnrichLog()
  );

  var resolvedCerts = resolvedCertificateQuery.result || [];

  var certMap = {};
  resolvedCerts.forEach((cert) => {
    certMap[cert._id] = cert;
  });

  if (providerOrgRefs.length > 0) {
    const providerOrgFilter = queryIdFilterFromIds(providerOrgRefs);
    logger.info(
      `Querying reference Id's to provider Organisations, [{}]`,
      endpointEnrichLog()
    );
    const providerOrgs = openidm.query(
      `${dpOrgManagedObjectKey}`,
      {
        _queryFilter: providerOrgFilter,
      },
      ["name", "type", "abn"]
    );
    logger.info(
      `Successfully identified provider Organisations, [{}]`,
      endpointEnrichLog()
    );
    // TODO extract these try-catch statements into functions to simplify error handling and assign directly to a const
    /** @type {MapOrganisationData} */
    var providerOrgMap;
    try {
      const providerOrgResults = providerOrgs.result;
      providerOrgMap = mapOrganisationData(providerOrgResults);
      logger.info(
        `Succesfully mapped provider Organisations, [{}]`,
        endpointEnrichLog()
      );
    } catch (error) {
      logger.error(
        `Failed to complete mapping of providerOrgs. Error: [${error.toString()}], [{}]`,
        endpointEnrichLog()
      );
      throw {
        code: 500,
        message: `Internal server error`,
      };
    }
  }

  var aggregatorOrgs;
  if (aggregatorOrgRefs.length > 0) {
    const aggregatorOrgFilter = queryIdFilterFromIds(aggregatorOrgRefs);
    try {
      logger.info(
        `Querying reference Id's to aggregator Organisations, [{}]`,
        endpointEnrichLog()
      );
      aggregatorOrgs = openidm.query(
        `${dpOrgManagedObjectKey}`,
        {
          _queryFilter: aggregatorOrgFilter,
        },
        ["name", "type", "abn"]
      );
      logger.info(
        `Successfully identified aggregator Organisations, [{}]`,
        endpointEnrichLog()
      );
    } catch (error) {
      logger.error(
        `Failed to query aggregatorOrgs [${error.toString()}], [{}]`,
        endpointEnrichLog()
      );
      throw {
        code: 500,
        message: `Internal server error`,
      };
    }
    /** @type {MapOrganisationData} */
    var aggregatorOrgMap;
    try {
      const aggregatorOrgsResults = aggregatorOrgs.result;
      aggregatorOrgMap = mapOrganisationData(aggregatorOrgsResults);
      logger.info(
        `Successfully mapped aggregator Organisations, [{}]`,
        endpointEnrichLog()
      );
    } catch (error) {
      logger.error(
        `Failed to complete mapping of aggregatorOrg [${error.toString()}], [{}]`,
        endpointEnrichLog()
      );
      throw {
        code: 500,
        message: `Internal server error`,
      };
    }
  }
  try {
    const resolvedfinal = deviceData.map((device) => {
      //Map Certificates first
      var resolvedCertsForDevice = (device.certificates || [])
        .map((certRef) => certMap[certRef._refResourceId])
        .filter(Boolean)
        .map(function (cert) {
          return {
            certificateExpiry: cert.certificateExpiry,
            certificateStatus: cert.certificateStatus,
          };
        });
      //Get providerOrg info
      var providerOrgInfo = null;
      if (device.organisation && device.organisation._refResourceId) {
        providerOrgInfo =
          providerOrgMap[device.organisation._refResourceId] || null;
      }
      //Get aggregatorOrgInfo if it exists
      var aggregatorOrgInfo = null;
      if (device.aggregator && device.aggregator._refResourceId) {
        aggregatorOrgInfo =
          aggregatorOrgMap[device.aggregator._refResourceId] || null;
      }
      //Combine
      var result = {
        deviceName: device.name,
        deviceId: device._id,
        deviceStatus: device.status,
        deviceExpiry: device.deviceExpiry,
        deviceEnvironment: device.environment,
        deviceType: device.type,
        certificates: resolvedCertsForDevice,
        provider: providerOrgInfo,
      };
      //Aggregator if it exists
      if (aggregatorOrgInfo) {
        result.aggregator = aggregatorOrgInfo;
      }
      return result;
    });
    return {
      device: resolvedfinal,
    };
  } catch (error) {
    logger.error(
      `Failed while resolving devices. Error: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Internal server error",
    };
  }
}

/**
 * @param {RequestContext} _requestContext
 * @returns {PolicyResult}
 */
function getAggregatorListPolicy(_requestContext) {
  return { success: true };
}

/**
 * @typedef {{
 * aggregatorOrgs: { name: string, type: string, abn: string}
 * }} getAggregatorList
 */

/**
 * Performs the operation to retrieve a list of aggregators that a provider manages
 *
 * @param {RequestContext} requestContext
 * @returns {getAggregatorList}
 */
function getAggregatorList(requestContext) {
  const orgs = openidm.query(
    `${dpOrgManagedObjectKey}`,
    {
      _queryFilter: `abn eq "${requestContext.query["abn"]}"`,
    },
    ["name", "abn", "_id", "aggregators/*", "type"]
  );

  if (orgs.resultCount === 0) {
    const missingOrgErrorMessage = `No digital partner organisation with ABN [${requestContext.query["abn"]}] found`;
    logger.warn(`${missingOrgErrorMessage} [{}]`, endpointEnrichLog());
    throw {
      code: 404,
      message: missingOrgErrorMessage,
    };
  }

  if (orgs.resultCount > 1) {
    const duplicateOrgErrorMessage = `Multiple provider digital partner organisations with ABN [${requestContext.query["abn"]}] found`;
    logger.error(`${duplicateOrgErrorMessage} [{}]`, endpointEnrichLog());
    throw {
      code: 500,
      message: duplicateOrgErrorMessage,
    };
  }

  if (orgs.result[0].type != "provider") {
    throw {
      code: 403,
      message: `Only a provider organisation is able to view aggregators organsisations `,
    };
  }

  const aggregatorOrgs = orgs.result[0].aggregators
    .filter((org) => org.type === "aggregator")
    .map(({ name, abn, type }) => ({ name, abn, type }));
  return { aggregatorOrgs };
}

/**
 * Core logic used to activate a device in IDM .
 *
 * @param {string} csr - certificate signing request used to send to PKI server for signing
 * @param {string} deviceId - assigned id of the device record in IDM
 * @returns the output for the caller
 */
function activateDevice(csr, deviceId) {
  const config = retrieveConfig();

  logger.info(
    "Exchanging CSR for cert with PKI service..., [{}]",
    endpointEnrichLog()
  );
  const cert = exchangeCsrForCert(
    config.pkiTemplateId,
    config.pkiCaId,
    config.pkiEndpoint,
    config.pkiToken,
    csr
  );
  logger.info(
    "Successfully exchanged CSR for cert with PKI service, [{}]",
    endpointEnrichLog()
  );

  const expiryDate = parseCertificate(cert.cert);

  const deviceManagedObject = /** @type {Device} */ (
    openidm.read(`${deviceManagedObjectKey}/${deviceId}`, null, [
      "*",
      "organisation/*",
    ])
  );
  if (!deviceManagedObject) {
    logger.error(
      "Device with ID [{}] not found in IDM [{}]",
      deviceId,
      endpointEnrichLog()
    );
    throw {
      code: 404,
      message: "Device not found",
      detail:
        "Ensure the deviceId provided is the IDM UUID '_id', not the 'ciamId'",
    };
  }
  const vendorEnv = deviceManagedObject.environment;

  if (
    deviceManagedObject.status &&
    String(deviceManagedObject.status).toLowerCase() === "active"
  ) {
    logger.error(
      "Device with ID [{}] is already active [{}]",
      deviceId,
      endpointEnrichLog()
    );
    throw {
      code: 400,
      message:
        "Device is already active. " +
        `To generate a new client ID, the existing OAuth client associated with [${deviceManagedObject.name}] must be deactivated first`,
      detail: {
        name: deviceManagedObject.name,
        ciamId: deviceManagedObject.ciamId,
      },
    };
  }

  if (
    !deviceManagedObject.organisation ||
    (String(deviceManagedObject.organisation.type).toLowerCase() !==
      "provider" &&
      String(deviceManagedObject.organisation.type).toLowerCase() !==
      "providerViaAggregator")
  ) {
    logger.error(
      "Device with ID [{}] is not associated with a provider organisation [{}]",
      deviceId,
      endpointEnrichLog({
        deviceManagedObject: deviceManagedObject,
      })
    );
    throw {
      code: 400,
      message: "Device must be associated with a provider organisation",
    };
  }
  const orgNdisNumber = getOrgNdisNumber(
    deviceManagedObject.organisation,
    vendorEnv
  );
  if (!orgNdisNumber) {
    logger.error(
      "The org for the device has no NDIS number [{}]",
      endpointEnrichLog({
        deviceOrganisation: deviceManagedObject.organisation,
      })
    );
    throw {
      code: 400,
      message: `Device has no matching NDIS org with ABN [${deviceManagedObject.organisation.abn}]`,
    };
  }

  // Create the OAuth client in CIAM
  const oauthClientDetails = createDeviceOauthClientCallback(
    deviceManagedObject,
    cert.cert,
    expiryDate,
    cert.serialnumber
  );
  const clientId = oauthClientDetails.oauthClient;

  // Activate the device in Mulesoft
  const isMulesoftIntegrationEnabled =
    (vendorEnv === "prod" && config.vendorProdIsMulesoftIntegrationEnabled) ||
    (vendorEnv === "test" && config.vendorTestIsMulesoftIntegrationEnabled);
  if (isMulesoftIntegrationEnabled) {
    logger.info(
      `Creating device in Mulesoft..., [{}]`,
      endpointEnrichLog({
        vendorEnv,
        orgNdisNumber,
        ciamId: deviceManagedObject.ciamId,
      })
    );
    activateMulesoftDevice(
      vendorEnv === "prod"
        ? config.vendorProdMulesoftDomain
        : config.vendorTestMulesoftDomain,
      vendorEnv === "prod"
        ? config.vendorProdMulesoftCredentials
        : config.vendorTestMulesoftCredentials,
      orgNdisNumber,
      deviceManagedObject.ciamId,
      deviceManagedObject.name
    );
    logger.info(
      `Successfully created device in Mulesoft, [{}]`,
      endpointEnrichLog({
        vendorEnv,
        orgNdisNumber,
        ciamId: deviceManagedObject.ciamId,
      })
    );
  } else {
    logger.info(
      `Mulesoft integration is disabled for vendor [${vendorEnv}] environment, skipping device creation [{}]`,
      endpointEnrichLog()
    );
  }
  const deviceExpiryFormatted = deviceExpiry(config.expiryMonths);
  // Update the device managed object to reflect the activation status
  try {
    openidm.patch(`${deviceManagedObjectKey}/${deviceId}`, null, [
      {
        operation: "replace",
        field: "status",
        value: "active",
      },
      {
        operation: "replace",
        field: "deviceExpiry",
        value: `${deviceExpiryFormatted}`,
      },
    ]);
  } catch (error) {
    logger.error(
      `Failed to update device status to active for device ID [${deviceId}]: [${error.toString()}], [{}]`,
      endpointEnrichLog()
    );
    throw {
      code: 500,
      message: "Unexpectedly failed to activate device",
      detail: {
        name: deviceManagedObject.name,
        ciamId: deviceManagedObject.ciamId,
      },
    };
  }

  return {
    device: {
      deviceId: deviceId,
      name: deviceManagedObject.name,
      ciamId: deviceManagedObject.ciamId,
      type: deviceManagedObject.type,
      environment: deviceManagedObject.environment,
    },
    certificate: cert,
    oauthClientId: clientId,
  };
}

/**
 * @param {RequestContext} requestContext
 * @returns {PolicyResult}
 */
function activateDevicePolicy(requestContext) {
  const deviceId = extractActivationDeviceFields(requestContext).deviceId;
  // Get details from the incoming access token
  const tokenDetails = retrieveTokenDetails();

  // Check user and device relationship
  const checkPolicy = userDeviceRelationshipPolicy(tokenDetails, deviceId);

  if (!checkPolicy.success) {
    logger.warn(
      `User is not authorized to activate device [${deviceId
      }]: [${checkPolicy.error.message}], [{}]`,
      endpointEnrichLog()
    );
  }
  return checkPolicy;
}

/**
 * Performs the operation to activate a device.
 *
 * @param {RequestContext} requestContext
 * @returns the output for the caller
 */
function activateDeviceHandler(requestContext) {
  const { csr, deviceId } = extractActivationDeviceFields(requestContext);
  return activateDevice(csr, deviceId);
}

/**
 * Extracts a subset of HTTP headers from the request context based on a fixed whitelist.
 *
 * @returns {Object} An object containing only whitelisted headers (lowercased keys).
 */
function extractWhitelistedHeaders() {
  const rawHeaders = context.http.headers || {};

  //Fixed whitelist of headers to log
  const HEADER_WHITELIST = [
    "x-correlation-id",
    "x-forgerock-transactionid",
    "x-forwarded-for",
  ];

  // Build an object with keys normalized to lowercase
  const filteredHeaders = Object.keys(rawHeaders).reduce(function (acc, key) {
    const low = key.toLowerCase();
    if (HEADER_WHITELIST.includes(low)) {
      acc[low] = rawHeaders[key];
    }
    return acc;
  }, {});

  return filteredHeaders;
}

// Extract filtered headers once to be used throughout the script
const filteredHeaders = extractWhitelistedHeaders();

/**
 * Returns a structured object for logger.* calls.
 * Additional properties can be merged in by passing an optional `extra` object.
 *
 * @param {Object=} extra - extra key/value pairs to include in the log object.
 * @returns {Object} The enriched log object containing request context and extras.
 *
 * @example
 *   logger.info("Created activation-codes event [{}]", endpointEnrichLog());
 *   logger.info("Created activation-codes event [{}]", endpointEnrichLog({ userId: userId }));
 *   try { … } catch (err) {
 *       logger.error("Failure [{}]", endpointEnrichLog({ err: err }));
 *       throw err;
 *   }
 *
 */
function endpointEnrichLog(extra) {
  // caller‑supplied data or empty object
  extra = extra || {};

  //build the base log object
  const enriched = {
    transactionId:
      // @ts-expect-error - legacy
      (context.transactionId && context.transactionId.id) || "unknown",
    // @ts-expect-error - legacy
    method: context.http.method,
    path: request.resourcePath,
    headers: filteredHeaders || {},
    body: request.content || {},
    query: request.additionalParameters,
    // @ts-expect-error - legacy
    parameters: request.parameters,
  };

  //merge caller‑supplied fields (extra wins on collision of propertynames)
  return _.assign(enriched, extra);
}

/**
 * Performs the validation requirements for the request
 * @returns an apiRef that contains the variables for the operation to be performed.
 */
function validateRequest() {
  // Extract the payload from the request
  const requestObjects = {
    body: Object.assign({}, request.content),
    query: Object.assign({}, request.additionalParameters),
    headers: Object.assign({}, context.http.headers),
  };
  // extract the apiVersion from the request
  var apiVersion = request.resourcePath.split("/")[0];
  // Check to see if the apiVersion has been defined.
  // If not return a 404 error indicating the apiVersion cannot be found.
  // @ts-expect-error - legacy
  if (!Object.keys(apis).includes(apiVersion)) {
    throw {
      code: 404,
      message: "API Not Found",
    };
  }
  // Check the nested API path
  var apiPath = request.resourcePath.split("/")[1];
  if (!apiPath || !Object.keys(apis[apiVersion]).includes(apiPath)) {
    throw {
      code: 404,
      message: "API Not Found",
    };
  }
  // extract the configuration for the operation to be performed.
  // if no configuration is found then return a 405 error saying the method is not supported.
  // @ts-expect-error - legacy
  var apiRef = apis[apiVersion][apiPath][context.http.method];
  if (!apiRef) {
    throw {
      code: 405,
      message: "Method Not Allowed",
    };
  }
  // Check to see if we have a contentType define and it matches the request.
  // If not then return a 415 error saying the requested payload is not supported.
  if (
    apiRef.contentType &&
    requestObjects.headers["Content-Type"] !== apiRef.contentType
  ) {
    throw {
      code: 415,
      message: "Incorrect Content Type",
    };
  }
  logger.info(`${request.resourcePath}: [{}]`, endpointEnrichLog());
  // Check the payload and validate
  // Define an empty detail object
  // @ts-expect-error - legacy
  details = [];
  // Loop through the required inputs and check to see if they are required
  apiRef.validators.forEach((validator) => {
    const obj = requestObjects[validator.type];
    if (obj === undefined) {
      logger.error("Validator is misconfigured: [{}]", endpointEnrichLog());
      throw {
        code: 500,
        message: "Internal Service Error",
      };
    }
    const value = obj[validator.name];
    // if the required attribute is not present add it to the list of required fields
    if (validator.required && value === undefined) {
      // @ts-expect-error - legacy
      details.push({
        required: validator.name,
      });
    }
    if (
      validator.pattern &&
      value !== undefined &&
      !validator.pattern.test(value)
    ) {
      // @ts-expect-error - legacy
      details.push({
        invalid: validator.name,
        pattern: validator.pattern.toString(),
        message: validator.errorMessage(validator, value),
      });
    }
  });
  // Loop through the rest of the values to see if there are any optional inputs
  const unknowns = [];
  Object.keys(requestObjects).forEach((key) => {
    if (key !== "headers") {
      Object.keys(requestObjects[key]).forEach((name) => {
        if (
          !_.find(apiRef.validators, {
            name: name,
            type: key,
          })
        ) {
          unknowns.push(`${key}:${name}`);
        }
      });
    }
  });
  // Log warning if there are any unknown values, but don't throw an error
  if (unknowns.length > 0) {
    logger.warn(
      "Unknown parameters [{}]",
      endpointEnrichLog({
        unknowns: unknowns,
      })
    );
  }
  // Check to see if we have any errors to report
  // @ts-expect-error - legacy
  if (details.length > 0) {
    throw {
      code: 400,
      message: `Bad Request`,
      // @ts-expect-error - legacy
      detail: details,
    };
  }
  // All good so return the config
  return {
    config: apiRef,
    request: requestObjects,
  };
}

(function () {
  const apiRef = validateRequest();
  const requestContext = apiRef.request;
  const policyResult = apiRef.config.policy(requestContext);
  /*if (!policyResult.success) {
    logger.warn(
      `Policy check failed for [${request.resourcePath}]: [${policyResult.error.message}], [{}]`,
      endpointEnrichLog()
    );
    throw policyResult.error;
  }*/

  return apiRef.config.operation(requestContext);
})();
