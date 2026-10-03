export const ORCEL_MODEL_CONFIG_ID = "orcel.authored_model";

export function fixedModelResult(modelId: string): Record<string, unknown> {
  const option = {
    type: "select",
    id: ORCEL_MODEL_CONFIG_ID,
    configId: ORCEL_MODEL_CONFIG_ID,
    name: "Model",
    displayName: "Model",
    category: "model",
    currentValue: modelId,
    options: [{ value: modelId, name: modelId, displayName: modelId }],
  };
  return {
    configOptions: [option],
    models: {
      currentModelId: modelId,
      availableModels: [{ modelId, name: modelId }],
    },
  };
}

export function isFixedModelRequest(
  method: string,
  params: Record<string, unknown> | undefined,
  modelId: string,
): boolean {
  return (
    (method === "session/set_config_option" &&
      params?.configId === ORCEL_MODEL_CONFIG_ID &&
      params.value === modelId) ||
    (method === "session/set_model" && params?.modelId === modelId)
  );
}
