const _ = require("lib/lodash");
const activationCodeLength = identityServer.getProperty(
  "esv.activation_code.length"
);
const activationCodeExpiryMinutes = identityServer.getProperty(
  "esv.activation_code.expiry_minutes"
);
const apis = {
  v1: {
    POST: {
      contentType: "application/json",
      validators: [
        {
          name: "id",
          type: "body",
          required: true,
          pattern: /^[-_a-zA-Z0-9]+$/,
          errorMessage: (validator, value) =>
            `'${value}' is not a valid user identifier '${validator.name}'.`,
        },
        {
          name: "type",
          type: "body",
          required: true,
          pattern: /^NDIS$/,
          errorMessage: (validator, value) =>
            `'${value}' is not a valid type for '${validator.name}'. Should be NDIS`,
        },
      ],
      managedObject: "managed/alpha_user",
      searchKey: "frIndexedMultivalued1",
      operation: "POSTv1",
    },
    GET: {
      validators: [
        {
          name: "id",
          type: "query",
          required: true,
          pattern: /^[-_a-zA-Z0-9]+$/,
          errorMessage: (validator, value) =>
            `'${value}' is not a valid user identifier '${validator.name}'.`,
        },
        {
          name: "type",
          type: "query",
          required: true,
          pattern: /^NDIS$/,
          errorMessage: (validator, value) =>
            `'${value}' is not a valid type for '${validator.name}'. Should be NDIS`,
        },
      ],
      managedObject: "managed/alpha_user",
      searchKey: "frIndexedMultivalued1",
      operation: "GETv1",
    },
  },
};
/**
 * Function generates an x digit OTP
 * @param {*} digits
 * @returns the generated OTP
 */
function generateOTP(length) {
  var characters = "0123456789";
  var secureRandom = new java.security.SecureRandom();
  var res = "";
  for (var i = 0; i < length; i++) {
    var index = secureRandom.nextInt(characters.length);
    res += characters.charAt(index);
  }
  return res;
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
      (context.transactionId && context.transactionId.id) || "unknown",
    method: context.http.method,
    path: request.resourcePath,
    headers: filteredHeaders || {},
    body: request.content || {},
    query: request.additionalParameters,
    parameters: request.parameters,
  };

  //merge caller‑supplied fields (extra wins on collision of propertynames)
  return _.assign(enriched, extra);
}

/**
 * Performs the operation for a POST / create request.
 * @param {*} apiRef
 * @returns the output for the caller
 */
function POSTv1(apiRef) {
  const _queryFilter = `${apiRef.config.searchKey} eq '${apiRef.request.body["id"]}'`;
  var userDetails = openidm.query(
    apiRef.config.managedObject,
    {
      _queryFilter,
    },
    ["_id", "userName", "frIndexedMultivalued1"]
  );
  if (userDetails.resultCount !== 1) {
    if (userDetails.resultCount === 0) {
      logger.info(
        "/endpoint/activation-codes: NDIS number not found [{}]",
        endpointEnrichLog({ resultCount: userDetails.resultCount })
      );
      throw {
        code: 404,
        message: "id not found",
      };
    } else {
      logger.info(
        "/endpoint/activation-codes: NDIS number not unique [{}]",
        endpointEnrichLog({ resultCount: userDetails.resultCount })
      );
      throw {
        code: 404,
        message: "Multiple ids found",
      };
    }
  }
  var timestamp = new Date();
  var expiry = new Date(
    timestamp.getTime() + activationCodeExpiryMinutes * 60 * 1000
  );
  var code = generateOTP(activationCodeLength);
  patchValue = {
    timestamp: timestamp.toISOString(),
    expiry: expiry.toISOString(),
    code: code,
    status: "Active",
  };
  // Update frIndexedMultivalued3 to include the necessary details
  openidm.patch(
    apiRef.config.managedObject + "/" + userDetails.result[0]._id,
    null,
    [
      {
        operation: "add",
        field: "/custom_historicalActivationCodes/-",
        value: patchValue,
      },
      {
        operation: "add",
        field: "/frIndexedString2",
        value: `${code}`,
      },
      {
        operation: "add",
        field: "/frIndexedDate2",
        value: expiry.toISOString(),
      },
    ]
  );
  logger.info(
    "/endpoint/activation-codes: Generated activation code [{}]",
    endpointEnrichLog({
      ciamId: userDetails.result[0].userName,
      ndisNumber: userDetails.result[0].frIndexedMultivalued1,
    })
  );
  return patchValue;
}

/**
 * Performs the operation for a GET / read request.
 * @param {*} apiRef
 * @returns the output for the caller
 */
function GETv1(apiRef) {
  const _queryFilter = `${apiRef.config.searchKey} eq '${apiRef.request.query["id"]}'`;
  var userDetails = openidm.query(
    apiRef.config.managedObject,
    {
      _queryFilter,
    },
    ["custom_historicalActivationCodes", "userName", "frIndexedMultivalued1"]
  );
  if (userDetails.resultCount !== 1) {
    if (userDetails.resultCount === 0) {
      logger.info(
        "/endpoint/activation-codes: NDIS number not found [{}]",
        endpointEnrichLog({ resultCount: userDetails.resultCount })
      );
      throw {
        code: 404,
        message: "id not found",
      };
    } else {
      logger.info(
        "/endpoint/activation-codes: NDIS number not unique [{}]",
        endpointEnrichLog({ resultCount: userDetails.resultCount })
      );
      throw {
        code: 404,
        message: "Multiple ids found",
      };
    }
  }
  logger.info(
    "/endpoint/activation-codes: Got activation codes [{}]",
    endpointEnrichLog({
      ciamId: userDetails.result[0].userName,
      ndisNumber: userDetails.result[0].frIndexedMultivalued1,
    })
  );
  return { events: userDetails.result[0].custom_historicalActivationCodes };
}

/**
 * Performsthe validation requirements for the request
 * @returns an apiRef that contains the varaibles for the operation to be performed.
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
  if (!Object.keys(apis).includes(apiVersion)) {
    throw {
      code: 404,
      message: "API Not Found",
    };
  }
  // extract the configuration for the operation to be performed.
  // if no configuration is found then return a 405 error saying the method is not supported.
  var apiRef = apis[apiVersion][context.http.method];
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
  logger.info("/endpoint/activation-codes: [{}]", endpointEnrichLog());
  // Check the payload and validate
  // Define an empty detail object
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
      details.push({ required: validator.name });
    }
    if (
      validator.pattern &&
      value !== undefined &&
      !validator.pattern.test(value)
    ) {
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
        if (!_.find(apiRef.validators, { name: name, type: key }))
          unknowns.push(`${key}:${name}`);
      });
    }
  });
  // Log warning if there are any unknown values, but don't throw an error
  if (unknowns.length > 0) {
    logger.warn(
      "Unknown parameters [{}]",
      endpointEnrichLog({ unknowns: unknowns })
    );
  }
  // Check to see if we have any errors to report
  if (details.length > 0) {
    throw {
      code: 400,
      message: `Bad Request`,
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
  extractWhitelistedHeaders();
  var apiRef = validateRequest();
  return this[apiRef.config.operation](apiRef);
})();