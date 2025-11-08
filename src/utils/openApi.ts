import { OpenAPI } from "openapi-types";
import openapiTS, { astToString } from "openapi-typescript";
import { EndpointMethod, IdmApi, idmApiSchema, nestedApiSchema } from "./idm";

const idmMethodToOpenApiMethod = (endpointMethod: EndpointMethod) => {
  const requestBody = endpointMethod.validators?.filter(
    (v) => v.type === "body"
  );
  const queryParameters = endpointMethod.validators?.filter(
    (v) => v.type === "query"
  );
  return {
    ...(requestBody && requestBody.length > 0
      ? {
          requestBody: {
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: Object.fromEntries(
                    requestBody.map((v) => [
                      v.name,
                      {
                        type: "string",
                        ...(v.pattern ? { pattern: v.pattern.source } : {}),
                      },
                    ]) || []
                  ),
                  required: requestBody
                    .filter((v) => v.required)
                    .map((v) => v.name),
                },
              },
            },
          },
        }
      : {}),
    ...(queryParameters && queryParameters.length > 0
      ? {
          parameters: queryParameters.map((v) => ({
            name: v.name,
            in: "query",
            required: v.required,
            schema: {
              type: "string",
              ...(v.pattern ? { pattern: v.pattern.source } : {}),
            },
          })),
        }
      : {}),
    responses: {
      "200": {
        description: "Successful response",
      },
    },
  };
};

const idmApiToOpenApiSpec = (idmApi: IdmApi): OpenAPI.Document => {
  const paths = Object.fromEntries(
    Object.entries(idmApi).map(([endpoint, methods]) => [
      `/${endpoint}`,
      Object.fromEntries(
        Object.entries(methods).map(([method, endpointMethod]) => [
          method.toLowerCase(),
          idmMethodToOpenApiMethod(endpointMethod as EndpointMethod),
        ])
      ),
    ])
  );

  return {
    openapi: "3.0.0",
    info: {
      title: "Converted IDM API",
      version: "1.0.0",
    },
    paths: paths,
    components: {},
  };
};

export const rawIdmSpecToOpenApiSpec = (
  rawIdmSpec: unknown
): OpenAPI.Document => {
  const parseResult = idmApiSchema.safeParse(rawIdmSpec);
  if (parseResult.success) {
    return idmApiToOpenApiSpec(parseResult.data);
  }

  const nestedParseResult = nestedApiSchema.safeParse(rawIdmSpec);
  if (!nestedParseResult.success) {
    console.error(
      "❌ IDM API spec validation failed:",
      nestedParseResult.error
    );
    process.exit(1);
  }
  const idmApi = nestedParseResult.data;
  // Join the nested path into a single path
  const flattenedApi: IdmApi = Object.fromEntries(
    Object.entries(idmApi)
      .map(([basePath, spec]) =>
        Object.entries(spec).map(([endpoint, methods]) => [
          `${basePath}/${endpoint}`,
          methods,
        ])
      )
      .flat()
  );
  return idmApiToOpenApiSpec(flattenedApi);
};

export const openApiToTypeDefs = async (openApiSpec: string) => {
  const ast = await openapiTS(openApiSpec);
  return astToString(ast);
};
