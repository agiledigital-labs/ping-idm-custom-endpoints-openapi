# IDM Custom Endpoint to OpenAPI Spec

Converts an IDM Custom Endpoint script to an OpenAPI/Swagger spec, along with TypeScript definitions.

TODO:

- Include return types
- Handle nested paths

## Usage

Export a script and place in the `./endpoints/` directory.

```sh
npm i
npm run build
npm run start -- openapi -f api.cjs 
```

The output will be in `./schemas/`.
