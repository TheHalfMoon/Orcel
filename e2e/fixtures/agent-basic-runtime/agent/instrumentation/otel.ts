import { otel } from "orcel/instrumentation/otel";

export default otel({ instrumentations: ["fetch"] });
