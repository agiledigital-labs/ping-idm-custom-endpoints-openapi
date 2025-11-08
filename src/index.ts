#!/usr/bin/env node

import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { convertSpecCommand, convertSpecConfig } from "./convertSpec";

void yargs(hideBin(process.argv))
  .scriptName("idm-api-spec-converter")
  .usage("Usage: $0 <command>")
  .demandCommand(1, "Please specify a command")
  .help()
  .env(true)
  .command(
    "openapi",
    "generate an OpenAPI schema from an IDM API definition",
    convertSpecConfig,
    convertSpecCommand
  )
  .parse();
