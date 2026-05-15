export const formatDate = (dateStr) => {
  const d = new Date(dateStr);
  return d.toLocaleDateString("fr-FR", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
};

export const truncatePath = (path, maxLen = 40) => {
  if (!path || path.length <= maxLen) return path;
  const parts = path.split("/");
  if (parts.length > 2) {
    return `.../${parts.slice(-2).join("/")}`;
  }
  return path.substring(0, maxLen) + "...";
};

export const maskSecret = (value) => {
  if (!value) return "";
  const visible = value.substring(0, 10);
  return visible + "********";
};
