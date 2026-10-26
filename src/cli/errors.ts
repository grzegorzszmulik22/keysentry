/** Only locally constructed diagnostics may cross the CLI error boundary. */
export class CliError extends Error {}
