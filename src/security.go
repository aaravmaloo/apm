package apm

func GetAvailableProfiles() []string {
	var names []string
	for k := range Profiles {
		names = append(names, k)
	}
	return names
}
