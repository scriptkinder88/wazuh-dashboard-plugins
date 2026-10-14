// Group names accepted by the Wazuh server API
const GROUP_NAME_RE = /^[\w.-]+$/;
const GROUP_NAME_MAX_LENGTH = 128;

/** Why a new group name is not valid, or undefined when it is. */
export const groupNameError = (name: string, existing: string[] = []) => {
  if (!GROUP_NAME_RE.test(name)) {
    return 'Use only letters, numbers, "_", "-" and "."';
  }
  if (name === '.' || name === '..') {
    return 'The name cannot be "." or ".."';
  }
  if (name.length > GROUP_NAME_MAX_LENGTH) {
    return `Use at most ${GROUP_NAME_MAX_LENGTH} characters`;
  }
  if (existing.includes(name)) {
    return 'This group already exists';
  }
  return undefined;
};
