import z from "zod";

const httpMethodSchema = z.enum(["GET", "POST", "PUT", "DELETE"]);

const regExpSchema = z.custom<RegExp>((val) => {
  return val instanceof RegExp;
});

const commonValidatorSchema = z.object({
  name: z.string(),
  required: z.boolean(),
  pattern: regExpSchema.optional(),
});

const bodyValidatorSchema = z.object({
  ...commonValidatorSchema.shape,
  type: z.literal("body"),
});

const queryValidatorSchema = z.object({
  ...commonValidatorSchema.shape,
  type: z.literal("query"),
});

const endpointMethodSchema = z.object({
  validators: z
    .array(z.union([bodyValidatorSchema, queryValidatorSchema]))
    .optional(),
});
export type EndpointMethod = z.infer<typeof endpointMethodSchema>;

export const idmApiSchema = z.record(
  z.string(),
  z.partialRecord(httpMethodSchema, endpointMethodSchema)
);
export type IdmApi = z.infer<typeof idmApiSchema>;

export const nestedApiSchema = z.record(z.string(), idmApiSchema);
