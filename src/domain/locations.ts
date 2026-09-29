export interface LocationChoice {
  locationId: string;
  name: string;
  status: string;
  currency: string | null;
}

export function selectActiveLocation(locations: readonly LocationChoice[]): LocationChoice | null {
  const active = locations.filter((location) => location.status === 'ACTIVE' && location.locationId.length > 0);
  active.sort((left, right) => left.locationId.localeCompare(right.locationId));
  return active[0] ?? null;
}
