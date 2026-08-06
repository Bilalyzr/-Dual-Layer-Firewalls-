/** EPIC H — resource attributes for OTel (service.name, version, env). */
export function getResourceAttributes(serviceName) {
  return {
    "service.name": serviceName,
    "service.version": process.env.npm_package_version || "1.0.0",
    "deployment.environment": process.env.NODE_ENV || "development",
    "host.name": process.env.HOSTNAME || "local",
  };
}
