package common

import (
	"net"
	"sync"

	"github.com/golang/glog"
	networkapi "github.com/openshift/api/network/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
)

type EgressDNSUpdate struct {
	UID       ktypes.UID
	Namespace string
}

type EgressDNSUpdates []EgressDNSUpdate

type EgressDNS struct {
	// Protects pdMap/namespaces operations
	lock sync.Mutex
	// holds DNS entries globally
	dns *DNS
	// this map holds which DNS names are in what policy objects
	dnsNamesToPolicies map[string]sets.String
	// Maintain namespaces for each policy to avoid querying etcd in syncEgressDNSPolicyRules()
	namespaces map[ktypes.UID]string

	// Report change when Add operation is done
	added chan bool

	// Report changes when there are dns updates
	Updates chan EgressDNSUpdates
}

func NewEgressDNS() (*EgressDNS, error) {
	dnsInfo, err := NewDNS("/etc/resolv.conf")
	if err != nil {
		utilruntime.HandleError(err)
		return nil, err
	}
	return &EgressDNS{
		dns:                dnsInfo,
		dnsNamesToPolicies: map[string]sets.String{},
		namespaces:         map[ktypes.UID]string{},
		added:              make(chan bool),
		Updates:            make(chan EgressDNSUpdates),
	}, nil
}

func (e *EgressDNS) Add(policy networkapi.EgressNetworkPolicy) {
	glog.V(2).Infof("EgressDNS.Add: acquiring lock for: %s/%s", policy.Namespace, policy.Name)
	e.lock.Lock()
	glog.V(2).Infof("EgressDNS.Add: acquired lock for: %s/%s", policy.Namespace, policy.Name)
	defer e.lock.Unlock()
	glog.V(2).Infof("EgressDNS.Add: released lock for: %s/%s", policy.Namespace, policy.Name)

	for _, rule := range policy.Spec.Egress {
		if len(rule.To.DNSName) > 0 {
			if _, exists := e.dnsNamesToPolicies[rule.To.DNSName]; !exists {
				e.dnsNamesToPolicies[rule.To.DNSName] = sets.NewString(string(policy.UID))
				//only call Add if the dnsName doesn't exist in the dnsNamesToPolicies
				if err := e.dns.Add(rule.To.DNSName); err != nil {
					utilruntime.HandleError(err)
				}
				e.signalAdded()
			} else {
				e.dnsNamesToPolicies[rule.To.DNSName].Insert(string(policy.UID))
			}
		}
	}
	e.namespaces[policy.UID] = policy.Namespace
}

func (e *EgressDNS) Delete(policy networkapi.EgressNetworkPolicy) {
	glog.V(2).Infof("EgressDNS.Delete: acquiring lock for: %s/%s", policy.Namespace, policy.Name)
	e.lock.Lock()
	glog.V(2).Infof("EgressDNS.Delete: acquired lock for: %s/%s", policy.Namespace, policy.Name)
	defer e.lock.Unlock()
	defer glog.V(2).Infof("EgressDNS.Delete: released lock for: %s/%s", policy.Namespace, policy.Name)
	//delete the entry from the dnsNames to UIDs map for each rule in the policy
	//if the slice is empty at this point, delete the entry from the dns object too
	//also remove the policy entry from the namespaces map.
	for _, rule := range policy.Spec.Egress {
		if len(rule.To.DNSName) > 0 {
			if uids, ok := e.dnsNamesToPolicies[rule.To.DNSName]; ok {
				uids.Delete(string(policy.UID))
				if uids.Len() == 0 {
					e.dns.Delete(rule.To.DNSName)
					delete(e.dnsNamesToPolicies, rule.To.DNSName)
				} else {
					e.dnsNamesToPolicies[rule.To.DNSName] = uids
				}
			}
		}
	}

	if _, ok := e.namespaces[policy.UID]; ok {
		delete(e.namespaces, policy.UID)
	}
}

func (e *EgressDNS) HandleNameUpdates() {
	glog.V(2).Info("HandleNameUpdates Called")
	for update := range e.dns.Updates {
		glog.V(2).Infof("HandleNameUpdates got update for: %s", update)
		e.updateName(update)
		glog.V(2).Infof("HandleNameUpdates got updated: %s", update)
	}
}

func (e EgressDNS) updateName(dnsName string) {
	glog.V(2).Info("updateName: acquiring lock for %s", dnsName)
	e.lock.Lock()
	glog.V(2).Infof("updateName: acquired lock for: %s", dnsName)
	defer e.lock.Unlock()
	defer glog.V(2).Info("updateName: released lock for %s", dnsName)
	policyUpdates := make([]EgressDNSUpdate, 0)

	if uids, exists := e.dnsNamesToPolicies[dnsName]; exists {
		for uid := range uids {
			glog.V(2).Infof("updateName: Adding uid %v because %s", uid, dnsName)
			policyUpdates = append(policyUpdates, EgressDNSUpdate{ktypes.UID(uid), e.namespaces[ktypes.UID(uid)]})
		}
	} else {
		glog.V(2).Infof("updateName: idn't find any entry for dns name: %s in the dns map.", dnsName)
	}

	glog.V(2).Infof("updateName: writing to channel for %s", dnsName)
	e.Updates <- policyUpdates
	glog.V(2).Infof("updateName: channel updated for %s", dnsName)
}

func (e *EgressDNS) GetIPs(dnsName string) []net.IP {
	glog.V(2).Infof("GetIPs acquiring lock for %s", dnsName)
	e.lock.Lock()
	glog.V(2).Infof("GetIPs acquired lock for %s", dnsName)
	defer e.lock.Unlock()
	defer glog.V(2).Infof("GetIPs released lock for %s", dnsName)
	return e.dns.Get(dnsName).ips

}

func (e *EgressDNS) GetNetCIDRs(dnsName string) []net.IPNet {
	cidrs := []net.IPNet{}
	for _, ip := range e.GetIPs(dnsName) {
		// IPv4 CIDR
		cidrs = append(cidrs, net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
	}
	return cidrs
}

func (e *EgressDNS) signalAdded() {
	// Non-blocking op
	select {
	case e.added <- true:
	default:
	}
}
