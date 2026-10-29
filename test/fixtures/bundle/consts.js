var apiRoot = "/api/v3";
export function listTeams() {
  return fetch(apiRoot + "/teams", { method: "GET" });
}
export function inviteMember(team) {
  return fetch(apiRoot + "/teams/" + team.teamId + "/invitations", { method: "POST" });
}
