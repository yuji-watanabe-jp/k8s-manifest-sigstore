//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/k8smanifest"

	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

const tlsDir = `/run/secrets/tls`

// +kubebuilder:webhook:path=/validate-resource,mutating=false,failurePolicy=ignore,sideEffects=NoneOnDryRun,groups=*,resources=*,verbs=create;update,versions=*,name=k8smanifest.sigstore.dev,admissionReviewVersions={v1,v1beta1}

type k8sManifestHandler struct {
	Client client.Client
}

func (h *k8sManifestHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	log.Info("[DEBUG] request: ", req.Kind, ", ", req.Name)

	var obj unstructured.Unstructured
	objectBytes := req.AdmissionRequest.Object.Raw
	err := json.Unmarshal(objectBytes, &obj)
	if err != nil {
		log.Errorf("failed to Unmarshal a requested object into %T; %s", obj, err.Error())
		return admission.Allowed("error but allow for development")
	}
	objList := []unstructured.Unstructured{obj}
	imageRef := ""
	keyPath := ""
	result, err := k8smanifest.VerifyResource(objList, imageRef, keyPath)
	if err != nil {
		log.Errorf("failed to check a requested resource; %s", err.Error())
		return admission.Allowed("error but allow for development")
	}
	log.Info("[DEBUG] result:", result)
	if !result.Verified {
		message := "no signature found"
		if result.Diff != nil && result.Diff.Size() > 0 {
			message = fmt.Sprintf("diff found: %s", result.Diff.String())
		}
		return admission.Denied(message)
	}
	return admission.Allowed("no checks here!")
}

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = corev1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "22a603b9.sigstore.dev",
		CertDir:            tlsDir,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/validate-resource", &webhook.Admission{Handler: &k8sManifestHandler{Client: mgr.GetClient()}})

	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
