const ZONES = {
  ciel1: { label: "Labo CIEL 1" },
  ciel2: { label: "Labo CIEL 2" },
  physique: { label: "Labo Serveur / Physique" },
};

// PET-7050 : contacts NF, HIGH = fermé/repos, LOW = ouvert/alerte (d'où inverted)
const DI_MAP = [
  { ch: 4, zone: "ciel1", label: "Détecteur mouvement CIEL 1", type: "mouvement", inverted: true },
  { ch: 5, zone: "ciel1", label: "Porte transition CIEL 1-2 / fenêtre", type: "porte", inverted: true },
  { ch: 6, zone: "ciel2", label: "Détecteur mouvement CIEL 2", type: "mouvement", inverted: true },
  { ch: 7, zone: "ciel2", label: "Porte CIEL 2 + fenêtre", type: "porte", inverted: true },
  { ch: 8, zone: "physique", label: "Détecteur mouvement Physique", type: "mouvement", inverted: true },
  { ch: 9, zone: "physique", label: "Portes Physique + fenêtre + bureau", type: "porte", inverted: true },
];

// Sorties PET-7067
const DO_MAP = [
  { ch: 0, zone: "ciel1", role: "gache", label: "Gâche" },
  { ch: 1, zone: "ciel1", role: "flash", label: "Flash" },
  { ch: 2, zone: "ciel1", role: "sirene", label: "Sirène" },
  { ch: 3, zone: "ciel2", role: "flash", label: "Flash" },
  { ch: 4, zone: "ciel2", role: "sirene", label: "Sirène" },
  { ch: 7, zone: "physique", role: "flash", label: "Flash" },
  { ch: 6, zone: "physique", role: "sirene", label: "Sirène" },
];

module.exports = { ZONES, DI_MAP, DO_MAP };
