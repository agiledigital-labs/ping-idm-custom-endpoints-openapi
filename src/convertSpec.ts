import fs from "fs";
import path from "path";
import { stringify as yamlStringify } from "yaml";
import { expressionToObject, rawScriptToObject } from "./utils/ast";
import { writeToFile } from "./utils/file";
import { openApiToTypeDefs, rawIdmSpecToOpenApiSpec } from "./utils/openApi";

import yargs from "yargs";

export const convertSpecConfig = (yargs: yargs.Argv) =>
  yargs.option("file", {
    alias: "f",
    describe: "Path to the file to convert",
    example: "endpoints/sample-endpoint.cjs",
    type: "string",
    demandOption: true,
  });

/**
 * Utility type to infer the generic type from yargs.Argv
 */
export type InferArgv<T> = T extends yargs.Argv<infer U> ? U : never;
export type ConvertSpecOptions = yargs.ArgumentsCamelCase<
  InferArgv<ReturnType<typeof convertSpecConfig>>
>;

export const convertSpecCommand = async (options: ConvertSpecOptions) => {
  console.log("🔄 Converting IDM API specification...");
  const filePath = options.file;
  const inputPath = path.resolve(`endpoints/${filePath}`);
  const outputPath = path.resolve(`schemas/${filePath}`);
  const endpointScript = fs.readFileSync(inputPath, "utf-8");

  const idmApiSpecNodes = rawScriptToObject(endpointScript, "apis");

  const idmApiSpec = expressionToObject(idmApiSpecNodes);
  const openApiSpec = rawIdmSpecToOpenApiSpec(idmApiSpec);

  const apiYaml = yamlStringify(openApiSpec);
  const apiYamlExtension = "-schema.yaml";
  writeToFile(outputPath, apiYamlExtension, apiYaml);
  console.log(
    `✅ OpenAPI schema written to ${path.basename(outputPath, path.extname(outputPath))}${apiYamlExtension}`
  );

  const apiTypeDefs = await openApiToTypeDefs(JSON.stringify(openApiSpec));
  const apiTypeDefsExtension = apiTypeDefs.includes("export ")
    ? "-types.ts"
    : "-types.d.ts";
  writeToFile(outputPath, apiTypeDefsExtension, apiTypeDefs);
  console.log(
    `✅ Type definitions written to ${path.basename(outputPath, path.extname(outputPath))}${apiTypeDefsExtension}`
  );
};
