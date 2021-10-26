// Copyright Red Hat

package controllers

import (
	"context"
	"fmt"

	authv1alpha1 "github.com/identitatem/dex-operator/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TODO: not sure what client is here?
func isdexServerNotYetStarted(ds *authv1alpha1.DexServer, c client.Client) bool {
	return false
}

func isdexServerFinished(ds *authv1alpha1.DexServer) bool {
	return false
}

func updateStatus(ctx context.Context, ds *authv1alpha1.DexServer, c client.Client) (*authv1alpha1.DexServer, error) {
	if err := c.Status().Update(ctx, ds, &client.UpdateOptions{}); err != nil {
		return ds, fmt.Errorf("unable to update status %s/%s: %v", ds.Namespace, ds.Name, err)
	}
	return ds, nil
}
