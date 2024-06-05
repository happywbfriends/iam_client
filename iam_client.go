package iam_client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func NewIamClient(serviceId, iamURL string, logger Logger, httpClient *http.Client) *IamClient {
	return &IamClient{
		httpClient: httpClient,
		log:        logger,
		iamURL:     iamURL,
		serviceId:  serviceId,
	}
}

type IamClient struct {
	httpClient *http.Client
	log        Logger
	iamURL     string
	// serviceId имя сервиса, в котором используется клиент IAM
	serviceId string
}

func (c *IamClient) SetHTTPClient(httpClient *http.Client) {
	c.httpClient = httpClient
}

// GetTokenId обращается на ручку IAM /api/v2/getTokenId
func (c *IamClient) GetTokenId(code string) (resp IAMGetTokenIdResponse, err error) {
	uri := fmt.Sprintf("%s/api/v2/getTokenId?code=%s", c.iamURL, url.QueryEscape(code))
	httpResp, err := c.httpClient.Get(uri)
	if err != nil {
		c.log.Errorf("1C6aVU4V4oy36y3 %s", err)
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		c.log.Errorf("31huD0zwS8ANHrN non-200 status from %s: %d", uri, httpResp.StatusCode)
		return
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		c.log.Errorf("Xp114xR1HZE0bLK %s", err)
		return
	}

	err = json.Unmarshal(body, &resp)
	if err != nil {
		c.log.Errorf("sY0M56IIeoPAqbE %s", err)
		return
	}

	return
}

// GetAuthLink обращается на ручку IAM /api/v2/getAuthLink
func (c *IamClient) GetAuthLink(backURL string) (resp IAMGetAuthLinkResponse, err error) {
	uri := fmt.Sprintf("%s/api/v2/getAuthLink?backURL=%s", c.iamURL, url.QueryEscape(backURL))
	httpResp, err := c.httpClient.Get(uri)
	if err != nil {
		c.log.Errorf("eC2L08eZNsY9alR %s", err)
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		c.log.Errorf("vU4259mD2fXDCOq non-200 status from %s: %d", uri, httpResp.StatusCode)
		return
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		c.log.Errorf("rd3MK52NFYTlB6u %s", err)
		return
	}

	err = json.Unmarshal(body, &resp)
	if err != nil {
		c.log.Errorf("v3Q03YEv41HWX9H %s", err)
		return
	}

	_, err = url.ParseRequestURI(resp.RedirectUrl)
	if err != nil {
		c.log.Errorf("0EBu320VdH7ouZ4 Invalid auth link from IAM '%s', error: %s", resp.RedirectUrl, err)
		return
	}

	return
}

// GetTokenPermissions обращается на ручку IAM /api/v2/getTokenPermissions
func (c *IamClient) GetTokenPermissions(tokenId, serviceId, backURL string) (resp IAMGetTokenPermissionsResponse, err error) {
	request, err := json.Marshal(IAMGetTokenPermissionsRequest{
		Id:        tokenId,
		ServiceId: serviceId,
		BackURL:   backURL,
	})
	if err != nil {
		c.log.Errorf("q98SE7hiSGtmXnS %s", err)
		return
	}

	uri := fmt.Sprintf("%s/api/v2/getTokenPermissions", c.iamURL)
	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewBuffer(request))
	if err != nil {
		c.log.Errorf("f4Wu70BZxuIJ2Mj %s", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		c.log.Errorf("Cb7S95L71QoSz3P %s", err)
		return
	}
	defer httpResp.Body.Close()

	resp.HttpStatus = httpResp.StatusCode

	if httpResp.StatusCode != http.StatusOK {
		c.log.Errorf("b21Hos4IwNoigYu non-200 status from %s: %d", uri, httpResp.StatusCode)
		return
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		c.log.Errorf("pT00e5I9xhvvEtT %s", err)
		return
	}

	err = json.Unmarshal(body, &resp)
	if err != nil {
		c.log.Errorf("7Lb17VlVgMYXgDD %s", err)
		return
	}

	if resp.RedirectUrl != "" {
		_, err = url.ParseRequestURI(resp.RedirectUrl)
		if err != nil {
			c.log.Errorf("8Wey25Pxx42phIN Invalid auth link from IAM '%s', error: %s", resp.RedirectUrl, err)
			return
		}
	}

	return
}

// GetAccessKeyPermissions обращается на ручку IAM /api/v2/getAccessKeyPermissions
func (c *IamClient) GetAccessKeyPermissions(key, serviceId string) (resp IAMGetTokenPermissionsResponse, err error) {
	request, err := json.Marshal(IAMGetAccessKeyPermissionsRequest{
		Key:       key,
		ServiceId: serviceId,
	})
	if err != nil {
		c.log.Errorf("q98SE7hiSGtmXnS %s", err)
		return
	}

	uri := fmt.Sprintf("%s/api/v2/getAccessKeyPermissions", c.iamURL)
	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewBuffer(request))
	if err != nil {
		c.log.Errorf("7t5X2y1tXk7NFXf %s", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-Id", c.serviceId)

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		c.log.Errorf("m70Q5MfSHRslO10 %s", err)
		return
	}
	defer httpResp.Body.Close()

	resp.HttpStatus = httpResp.StatusCode

	if httpResp.StatusCode != http.StatusOK {
		c.log.Errorf("v6067JKnBcITSfT non-200 status from %s: %d", uri, httpResp.StatusCode)
		return
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		c.log.Errorf("3M6x29xVR1zIVPQ %s", err)
		return
	}

	err = json.Unmarshal(body, &resp)
	if err != nil {
		c.log.Errorf("ksH52NcV3ITXWDL %s", err)
		return
	}

	return
}

// GetTokenPermissions обращается на ручку IAM /api/v2/isTokenValid
func (c *IamClient) IsTokenValid(tokenId string) (resp IAMResponseSuccess, err error) {
	request, err := json.Marshal(IAMIsTokenValidRequest{
		Id: tokenId,
	})
	if err != nil {
		c.log.Errorf("fD03yh1rjphQhYq %s", err)
		return
	}

	uri := fmt.Sprintf("%s/api/v2/isTokenValid", c.iamURL)
	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewBuffer(request))
	if err != nil {
		c.log.Errorf("7UGjf18s83ynx7i %s", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		c.log.Errorf("iZ7097HnWDdiC4C %s", err)
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		c.log.Errorf("3G0S9nvGt6FUM9A non-200 status from %s: %d", uri, httpResp.StatusCode)
		return
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		c.log.Errorf("8F4p6oT6mg5R4E7 %s", err)
		return
	}

	err = json.Unmarshal(body, &resp)
	if err != nil {
		c.log.Errorf("tW785Mx4iL9HZnp %s", err)
		return
	}

	return
}
