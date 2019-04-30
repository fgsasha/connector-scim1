/*
 * Copyright (c) 2016 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.evolveum.polygon.scim;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.util.*;

import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.EntityTemplate;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.util.EntityUtils;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidCredentialException;
import org.identityconnectors.framework.common.exceptions.OperationTimeoutException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.AttributeFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.evolveum.polygon.scim.ErrorHandler;
import com.evolveum.polygon.scim.common.HttpPatch;

import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.http.entity.StringEntity;
import org.identityconnectors.framework.common.objects.AttributeBuilder;


/**
 * @author Macik
 * 
 *         An implementation of all strategy methods used for processing of
 *         data.
 * 
 */

public class WorkplaceHandlingStrategy implements HandlingStrategy {

	private static HttpClient httpClient;
	private static Header authHeader;
	private static String communityId;
	private static String firstAdminId;

	private static final Log LOGGER = Log.getLog(WorkplaceHandlingStrategy.class);
	private static final String CANONICALVALUES = "canonicalValues";
	private static final String REFERENCETYPES = "referenceTypes";
	private static final String RESOURCES = "Resources";
	private static final String STARTINDEX = "startIndex";
	private static final String TOTALRESULTS = "totalResults";
	private static final String ITEMSPERPAGE = "itemsPerPage";
	private static final String FORBIDENSEPPARATOR = ":";
	private static final String SEPPARATOR = "-";
	private static final char QUERYCHAR = '?';
	private static final char QUERYDELIMITER = '&';
	private static final String SCHEMAS = "schemas";
	private static final String SCHEMAVALUE = "urn:scim:schemas:core:1.0";
	private static final String ATTRIBUTES = "attributes";
	private static final String USERNAME = "userName";
	private static final String NAME = "name";
	private static final String NAMEFORMATED = "name.formatted";
	private static final String  ACTIVE = "active";
        
	
	private static final String READONLY = "readOnly";
	private static final String SCHEMA = "schema";
	private static final String REQUIRED = "required";
	private static final String CASEEXSACT = "caseExact";
	private static final String STRING = "string";
	private static final String ENTERPRISE="extensionenterprise";
	private static final String ENTERPRISEVALUE="urn:scim:schemas:extension:enterprise:1.0";
	static final String STARTTERMDATES="extensionstarttermdates";
	static final String STARTTERMDATESVALUE="urn:scim:schemas:extension:facebook:starttermdates:1.0";
	private static final String MANAGER="manager";
	private static final String MANAGERID="managerId";
	private static final String NULLSPECIAL="NULL";
	private static final String NULL="null";

	private static final String ADDRESSESATTRIBUTESFORMATTED="addresses.attributes.formatted";
	private static final String ADDRESSESATTRIBUTESPRIMARY="addresses.attributes.primary";
	private static final String EXTENSIONSTARTTERMDATESSTARTDATE="extensionstarttermdates.startDate";
	private static final String EXTENSIONSTARTTERMDATESENDDATE="extensionstarttermdates.endDate";
	private static final String EXTENSIONENTERPRISEDIVISION="extensionenterprise.division";
	private static final String EXTENSIONENTERPRISEMANAGER="extensionenterprise.manager";
	private static final String EXTENSIONENTERPRISEORGANIZATION="extensionenterprise.organization";
	private static final String EXTENSIONENTERPRISEDEPARTMENT="extensionenterprise.department";
	private static final String EXTENSIONENTERPRISECOSTCENTER="extensionenterprise.costCenter";
	private static final String EXTENSIONENTERPRISEEMPLOYEENUMBER="extensionenterprise.employeeNumber";
	private static final String EXTERNALID="externalId";

	private static final String GRAPH_API_BASE_URI="https://graph.facebook.com";


	public WorkplaceHandlingStrategy(ScimConnectorConfiguration conf) {
		httpClient = initHttpClient(conf);
		ServiceAccessManager accessManager = new ServiceAccessManager(conf);
		authHeader = accessManager.getAuthHeader();
		if (authHeader == null) {
			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}
		communityId = getCommunityId();

		if(communityId == null){
			throw new ConnectorException("Community ID is not found, please check if token is correct");
		}

		firstAdminId = getFirstAdminId();
		if(firstAdminId == null){
			throw new ConnectorException("Can not find any admin in community");
		}
	}

	@Override
	public Uid create(String resourceEndPoint, ObjectTranslator objectTranslator, Set<Attribute> attributes,
			Set<Attribute> injectedAttributeSet, ScimConnectorConfiguration conf) {

		ServiceAccessManager accessManager = new ServiceAccessManager(conf);

		String scimBaseUri = accessManager.getBaseUri();

		if (scimBaseUri.isEmpty()) {

			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}

		injectedAttributeSet = attributeInjection(injectedAttributeSet, accessManager.getLoginJson());

		JSONObject jsonObject = new JSONObject();
                LOGGER.info("Creation user. Input data: attributes={0} ; injectedAttributeSet={1}",attributes,injectedAttributeSet);
		//jsonObject = objectTranslator.translateSetToJson(attributes, injectedAttributeSet, resourceEndPoint);
                jsonObject = objectTranslator.translateSetToJson(attributes, injectedAttributeSet, resourceEndPoint);
                LOGGER.info("jsonObject={0}",jsonObject);
                //Normalize JSON
                jsonObject=normalizeJSON(jsonObject);
                LOGGER.info("jsonObject afert Normalization={0}",jsonObject);
                
		HttpClient httpClient = initHttpClient(conf);

		String uri = new StringBuilder(scimBaseUri).append(SLASH).append(resourceEndPoint).append(SLASH).toString();
		LOGGER.info("Query url: {0}", uri);
		try {

			// LOGGER.info("Json object to be send: {0}",
			// jsonObject.toString(1));

			HttpPost httpPost = buildHttpPost(uri,jsonObject);
			String responseString = null;
			try (CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpPost)) {

				HttpEntity entity = response.getEntity();

				if (entity != null) {
					responseString = EntityUtils.toString(entity);
				} else {
					responseString = "";
				}

				int statusCode = response.getStatusLine().getStatusCode();
				LOGGER.info("Status code: {0}", statusCode);

				if (statusCode == 201) {
					LOGGER.info("Creation of resource was successful");

					if (!responseString.isEmpty()) {
						JSONObject json = new JSONObject(responseString);
                                                //FIX
						Uid uid = new Uid(String.valueOf(json.getLong(ID)));

						 LOGGER.info("Json response: {0}", json.toString(1));
						return uid;
					} else {
						return null;
					}
				} else {
					handleInvalidStatus(" while resource creation, please check if credentials are valid. ",
							responseString, "creating a new object", statusCode);
				}

			} catch (ClientProtocolException e) {
				LOGGER.error(
						"An protocol exception has occurred while in the process of creating a new resource object. Possible mismatch in interpretation of the HTTP specification: {0}",
						e.getLocalizedMessage());
				LOGGER.info(
						"An protocol exception has occurred while in the process of creating a new resource object. Possible mismatch in interpretation of the HTTP specification: {0}",
						e);
				throw new ConnectionFailedException(
						"An protocol exception has occurred while in the process of creating a new resource object. Possible mismatch in interpretation of the HTTP specification: {0}",
						e);

			} catch (IOException e) {

				if ((e instanceof SocketTimeoutException || e instanceof NoRouteToHostException)) {

					throw new OperationTimeoutException(
							"The connection timed out. Occurrence in the process of creating a new resource object", e);
				} else {

					LOGGER.error(
							"An error has occurred while processing the http response. Occurrence in the process of creating a new resource object: {0}",
							e.getLocalizedMessage());
					LOGGER.info(
							"An error has occurred while processing the http response. Occurrence in the process of creating a new resource object: {0}",
							e);

					throw new ConnectorIOException(
							"An error has occurred while processing the http response. Occurrence in the process of creating a new resource object",
							e);
				}
			}

		} catch (JSONException e) {

			LOGGER.error(
					"An exception has occurred while processing an json object. Occurrence in the process of creating a new resource object: {0}",
					e.getLocalizedMessage());
			LOGGER.info(
					"An exception has occurred while processing an json object. Occurrence in the process of creating a new resource object: {0}",
					e);

			throw new ConnectorException(
					"An exception has occurred while processing an json object. Occurrence in the process of creating a new resource objec",
					e);
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("Unsupported encoding: {0}. Occurrence in the process of creating a new resource object ",
					e.getLocalizedMessage());
			LOGGER.info("Unsupported encoding: {0}. Occurrence in the process of creating a new resource object ", e);

			throw new ConnectorException(
					"Unsupported encoding, Occurrence in the process of creating a new resource object ", e);
		}
		return null;
	}

	@Override
	public void query(Filter query, StringBuilder queryUriSnippet, String resourceEndPoint,
			ResultsHandler resultHandler, ScimConnectorConfiguration conf) {

		LOGGER.info("Processing query");

		Boolean isCAVGroupQuery = false; // query is a ContainsAllValues
											// filter query for the group
											// endpoint?
		Boolean valueIsUid = false;
		ServiceAccessManager accessManager = new ServiceAccessManager(conf);

		Header authHeader = accessManager.getAuthHeader();
		String scimBaseUri = accessManager.getBaseUri();

		if (authHeader == null || scimBaseUri.isEmpty()) {

			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}

		String q;

		String[] baseUrlParts = scimBaseUri.split("\\.");
		String providerName = baseUrlParts[1];

		if (query != null) {

			if (query instanceof EqualsFilter) {
				Attribute filterAttr = ((EqualsFilter) query).getAttribute();

				if (filterAttr instanceof Uid) {

					valueIsUid = true;

					isCAVGroupQuery = checkFilter(query, resourceEndPoint);

					if (!isCAVGroupQuery) {
						q = ((Uid) filterAttr).getUidValue();
					} else {
						q = ((Uid) filterAttr).getUidValue();
						resourceEndPoint = "Users";
					}
				} else {

					isCAVGroupQuery = checkFilter(query, resourceEndPoint);

					if (!isCAVGroupQuery) {
						LOGGER.info("Attribute not instance of UID");
						q = qIsFilter(query, queryUriSnippet, providerName, resourceEndPoint);
					} else {
						q = (String) filterAttr.getValue().get(0);
						resourceEndPoint = "Users";
					}

				}

			} else {

				isCAVGroupQuery = checkFilter(query, resourceEndPoint);

				if (!isCAVGroupQuery) {
					q = qIsFilter(query, queryUriSnippet, providerName, resourceEndPoint);
				} else {

					Attribute filterAttr = ((AttributeFilter) query).getAttribute();
					q = (String) filterAttr.getValue().get(0);
					resourceEndPoint = "Users";
				}
			}

		} else {
			LOGGER.info("No filter was defined, query will return all the resource values");
			q = queryUriSnippet.toString();

		}
		HttpClient httpClient = initHttpClient(conf);

		if(resourceEndPoint.equals(GROUPS)){
			LOGGER.info("GROUP GRAPH");
			handleGroupQuery(resultHandler, q);
			return;
		}

		String uri = new StringBuilder(scimBaseUri).append(SLASH).append(resourceEndPoint).append(SLASH).append(q)
				.toString();
		LOGGER.info("Query url: {0}", uri);

		HttpGet httpGet = buildHttpGet(uri);
		String responseString = null;
		try (CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpGet)) {
			int statusCode = response.getStatusLine().getStatusCode();
			HttpEntity entity = response.getEntity();

			if (entity != null) {
				responseString = EntityUtils.toString(entity);
			} else {
				responseString = "";
			}
			LOGGER.info("Status code: {0}", statusCode);
			if (statusCode == 200) {

				if (!responseString.isEmpty()) {
					try {
						JSONObject jsonObject = new JSONObject(responseString);

						LOGGER.info("Json object returned from service provider: {0}", jsonObject.toString(1));
						if (jsonObject.has(RESOURCES)) {
							LOGGER.info("execute normalizeJSONFullRecon on jsonObject");
							jsonObject = normalizeJSONFullRecon(jsonObject);
						} else {
							LOGGER.info("execute normalizeJSON on jsonObject");
							jsonObject = normalizeJSON(jsonObject);
						}
						LOGGER.info("Json object after normalization: {0}", jsonObject.toString(1));

						try {

							if (valueIsUid) {

								if(jsonObject.has(USERNAME)){
									jsonObject = populateUserJsonWithGroup(jsonObject);
								}
								ConnectorObject connectorObject = buildConnectorObject(jsonObject, resourceEndPoint);
								resultHandler.handle(connectorObject);

							} else {

								if (isCAVGroupQuery) {

									handleCAVGroupQuery(jsonObject, GROUPS, resultHandler, scimBaseUri, authHeader,
											conf);

								} else if (jsonObject.has(RESOURCES)) {
									int amountOfResources = jsonObject.getJSONArray(RESOURCES).length();

									if(resourceEndPoint.equals("Users") && getNextStartIndex(jsonObject) != 0){
										jsonObject = getUsersFormOtherPages(jsonObject, uri, amountOfResources);
										amountOfResources = jsonObject.getJSONArray(RESOURCES).length();
									}

									for (int i = 0; i < amountOfResources; i++) {
										JSONObject minResourceJson = new JSONObject();
										minResourceJson = jsonObject.getJSONArray(RESOURCES).getJSONObject(i);
										if (minResourceJson.has(ID) && !minResourceJson.isNull(ID)) {

											if (minResourceJson.has(USERNAME)) {

												minResourceJson = populateUserJsonWithGroup(normalizeJSON(minResourceJson));

												ConnectorObject connectorObject = buildConnectorObject(minResourceJson,
														resourceEndPoint);

												resultHandler.handle(connectorObject);
											}
										} else {
											LOGGER.error("No uid present in fetched object: {0}", minResourceJson);

											throw new ConnectorException(
													"No uid present in fetchet object while processing queuery result");

										}
									}
								} else {

									LOGGER.error("Resource object not present in provider response to the query");

									throw new ConnectorException(
											"No uid present in fetchet object while processing queuery result");

								}
							}

						} catch (Exception e) {
							LOGGER.error(
									"Builder error. Error while building connId object. The exception message: {0}",
									e.getLocalizedMessage());
							LOGGER.info("Builder error. Error while building connId object. The excetion message: {0}",
									e);
							throw new ConnectorException("Builder error. Error while building connId object.", e);
						}

					} catch (JSONException jsonException) {
						if (q == null) {
							q = "the full resource representation";
						}
						LOGGER.error(
								"An exception has occurred while setting the variable \"jsonObject\". Occurrence while processing the http response to the queuey request for: {1}, exception message: {0}",
								jsonException.getLocalizedMessage(), q);
						LOGGER.info(
								"An exception has occurred while setting the variable \"jsonObject\". Occurrence while processing the http response to the queuey request for: {1}, exception message: {0}",
								jsonException, q);
						throw new ConnectorException(
								"An exception has occurred while setting the variable \"jsonObject\".", jsonException);
					}

				} else {

					LOGGER.warn("Service provider response is empty, responce returned on query: {0}", q);
				}
			} else if (statusCode == 401) {

				handleInvalidStatus("while querying for resources. ", responseString, "retrieving an object",
						statusCode);

			} else if (valueIsUid) {

				LOGGER.info("Abouth to throw an exception, the resource: {0} was not found.", q);

				ErrorHandler.onNoSuccess(responseString, statusCode, uri);

				StringBuilder errorBuilder = new StringBuilder("The resource with the uid: ").append(q)
						.append(" was not found.");

				throw new UnknownUidException(errorBuilder.toString());
			} else if (statusCode == 404) {

				String error = ErrorHandler.onNoSuccess(responseString, statusCode, uri);
				LOGGER.warn("Resource not found: {0}", error);
			} else {
				ErrorHandler.onNoSuccess(responseString, statusCode, uri);
			}

		} catch (IOException e) {

			if (q == null) {
				q = "the full resource representation";
			}

			StringBuilder errorBuilder = new StringBuilder(
					"An error occurred while processing the query http response for ");
			errorBuilder.append(q);
			if ((e instanceof SocketTimeoutException || e instanceof NoRouteToHostException)) {

				errorBuilder.insert(0, "The connection timed out while closing the http connection. ");

				throw new OperationTimeoutException(errorBuilder.toString(), e);
			} else {

				LOGGER.error(
						"An error occurred while processing the queuery http response. Occurrence while processing the http response to the queuey request for: {1}, exception message: {0}",
						e.getLocalizedMessage(), q);
				LOGGER.info(
						"An error occurred while processing the queuery http response. Occurrence while processing the http response to the queuey request for: {1}, exception message: {0}",
						e, q);
				throw new ConnectorIOException(errorBuilder.toString(), e);
			}
		}
	}

	@Override
	public void handleCAVGroupQuery(JSONObject jsonObject, String resourceEndPoint, ResultsHandler handler,
									String scimBaseUri, Header authHeader, ScimConnectorConfiguration conf)
			throws ClientProtocolException, IOException {

		ConnectorObject connectorObject = buildConnectorObject(jsonObject, resourceEndPoint);

		handler.handle(connectorObject);

	}


	private void handleGroupQuery(ResultsHandler resultHandler, String gid) {
		if(!gid.equals("")){
			JSONObject group = getGroup(gid);

			if(group.length() != 0) {
				ConnectorObject connectorObject = buildConnectorObject(group, GROUPS);
				resultHandler.handle(connectorObject);
				return;
			}
		}

		JSONObject groups = getGroups();

		int amountOfResources = groups.getJSONArray("data").length();

		for (int i = 0; i < amountOfResources; i++) {
			JSONObject group = groups.getJSONArray("data").getJSONObject(i);

			ConnectorObject connectorObject = buildConnectorObject(group, GROUPS);

			resultHandler.handle(connectorObject);
		}
	}

	@Override
	public Uid update(Uid uid, String resourceEndPoint, ObjectTranslator objectTranslator, Set<Attribute> attributes,
			ScimConnectorConfiguration conf) {
		ServiceAccessManager accessManager = new ServiceAccessManager(conf);

		Header authHeader = accessManager.getAuthHeader();
		String scimBaseUri = accessManager.getBaseUri();

		if (authHeader == null || scimBaseUri.isEmpty()) {

			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}

		HttpClient httpClient = initHttpClient(conf);

		if(resourceEndPoint.equals("Users")){
			LOGGER.info("USERS UPDATE GRAPH");
			String operation = objectTranslator.getOperation();

			for(Attribute attr : attributes){
				if(attr.getName().equals("groups")){
					for(Object val: attr.getValue()){
						if(operation.equals("delete")) {
							deleteUserFromGroup(uid.getUidValue(), val.toString());
						} else {
							addUserToGroup(uid.getUidValue(), val.toString());
						}
					}
					return uid;
				}

				if(attr.getName().equals("__ENABLE__")){
					for(Object val: attr.getValue()){
						if(val.toString().equals("false")) {
							addAdminToGroupsWhereUserIsLastMember(uid.getUidValue());
						}
					}

				}
			}
		}

		String uri = new StringBuilder(scimBaseUri).append(SLASH).append(resourceEndPoint).append(SLASH)
				.append(uid.getUidValue()).toString();
		LOGGER.info("The uri for the update request: {0}", uri);

                
		String responseString = null;
		try {                    
			
			LOGGER.info("Input attribute set: {0}",attributes);
			//attributes=nullAttributeHandler(attributes);
			JSONObject jsonObject = objectTranslator.translateSetToJson(attributes, null, resourceEndPoint);
			//TODO check and add missing attributes to attributeSet from resource
			JSONObject jsonUserOnResource = getCurrentUserData(uri);

			// When changing primary phone number, phone number should be added to updated JSON
			for(Attribute attr : attributes){
				if(attr.getName().equals("phoneNumbers.work.primary") && jsonObject.has("phoneNumbers") && jsonUserOnResource.has("phoneNumbers")){
					JSONArray phoneNumbers = jsonObject.getJSONArray("phoneNumbers");
					JSONArray phoneNumbersResource = jsonUserOnResource.getJSONArray("phoneNumbers");
					JSONArray phoneNumbersNew = new JSONArray();

					for (int i = 0; i < phoneNumbers.length(); i++) {
						JSONObject phone = phoneNumbers.getJSONObject(i);
						JSONObject phoneNew = phone;
						if(phoneNumbersResource.isNull(i)){
							continue;
						}
						JSONObject phoneResource = phoneNumbersResource.getJSONObject(i);

						if(!phone.has("value") && phoneResource.has("value")){
							phoneNew.put("value", phoneResource.getString("value"));
						}

						phoneNumbersNew.put(phoneNew);
					}
					jsonObject.put("phoneNumbers", phoneNumbersNew);
				}
			}

			jsonObject=getMissingMandatoryAttributes(jsonObject, jsonUserOnResource, getMandatoryAttributes());
                        
			LOGGER.info("The update json object: {0}", jsonObject);
			jsonObject=jsonObject.append(SCHEMAS, SCHEMAVALUE);
			LOGGER.info("The update json object after append: {0}", jsonObject);
			//Normalize JSON
			jsonObject=normalizeJSON(jsonObject);
			LOGGER.info("jsonObject afert Normalization={0}",jsonObject);

			LOGGER.info("The uri for the update request: {0}", uri);
			HttpPut httpPut = buildHttpPut(uri, jsonObject);
                            
			try (CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpPut)) {
                        
				int statusCode = response.getStatusLine().getStatusCode();

				HttpEntity entity = response.getEntity();

				if (entity != null) {
					responseString = EntityUtils.toString(entity);
				} else {
					responseString = "";
				}
				if (statusCode == 200 || statusCode == 201) {
					LOGGER.info("Update of resource was succesfull");

					if (!responseString.isEmpty()) {
						JSONObject json = new JSONObject(responseString);
						 LOGGER.ok("Json response: {0}", json.toString());
                                                //FIX
						Uid id = new Uid(String.valueOf(json.getLong(ID)));
						return id;

					} else {
						LOGGER.warn("Service provider response is empty, no response after the update procedure");
					}
				} else if (statusCode == 204) {

					LOGGER.warn("Status code {0}. Response body left intentionally empty", statusCode);

					return uid;
				} else if (statusCode == 404) {

					ErrorHandler.onNoSuccess(responseString, statusCode, uri);

					StringBuilder errorBuilder = new StringBuilder("The resource with the uid: ").append(uid)
							.append(" was not found.");

					throw new UnknownUidException(errorBuilder.toString());
				} else {
					handleInvalidStatus("while updating resource. ", responseString, "updating object", statusCode);
				}
			}
		} catch (UnsupportedEncodingException e) {

			LOGGER.error("Unsupported encoding: {0}. Occurrence in the process of updating a resource object ",
					e.getMessage());
			LOGGER.info("Unsupported encoding: {0}. Occurrence in the process of updating a resource object ", e);

			throw new ConnectorException(
					"Unsupported encoding, Occurrence in the process of updating a resource object ", e);

		} catch (JSONException e) {

			LOGGER.error(
					"An exception has occurred while processing a json object. Occurrence in the process of updating a resource object: {0}",
					e.getLocalizedMessage());
			LOGGER.info(
					"An exception has occurred while processing a json object. Occurrence in the process of updating a resource object: {0}",
					e);

			throw new ConnectorException(
					"An exception has occurred while processing a json object,Occurrence in the process of updating a resource object",
					e);
		} catch (ClientProtocolException e) {
			LOGGER.error(
					"An protocol exception has occurred while in the process of updating a resource object. Possible mismatch in the interpretation of the HTTP specification: {0}",
					e.getLocalizedMessage());
			LOGGER.info(
					"An protocol exception has occurred while in the process of updating a resource object. Possible mismatch in the interpretation of the HTTP specification: {0}",
					e);
			throw new ConnectionFailedException(
					"An protocol exception has occurred while in the process of updating a resource object, Possible mismatch in the interpretation of the HTTP specification.",
					e);
		} catch (IOException e) {

			StringBuilder errorBuilder = new StringBuilder(
					"An error has occurred while processing the http response. Occurrence in the process of updating a resource object wit the Uid: ");

			errorBuilder.append(uid.toString());

			if ((e instanceof SocketTimeoutException || e instanceof NoRouteToHostException)) {
				errorBuilder.insert(0, "The connection timed out. ");

				throw new OperationTimeoutException(errorBuilder.toString(), e);
			} else {

				LOGGER.error(
						"An error has occurred while processing the http response. Occurrence in the process of updating a resource object: {0}",
						e.getLocalizedMessage());
				LOGGER.info(
						"An error has occurred while processing the http response. Occurrence in the process of updating a resource object: {0}",
						e);

				throw new ConnectorIOException(errorBuilder.toString(), e);
			}
		} catch (Exception ex) {
                Logger.getLogger(WorkplaceHandlingStrategy.class.getName()).log(Level.SEVERE, null, ex);
            }
		return null;

	}

	private void addAdminToGroupsWhereUserIsLastMember(String uid) {
		JSONObject userGroups = getUserGroups(uid);

		int amountOfResources = userGroups.getJSONArray("data").length();

		for (int i = 0; i < amountOfResources; i++) {
			JSONObject group = userGroups.getJSONArray("data").getJSONObject(i);

			String gid = String.valueOf(group.getLong(ID));
			if(getGroupMembersCount(gid) <= 1){
				addUserToGroup(firstAdminId, gid);
			}
		}
	}

	@Override
	public void delete(Uid uid, String resourceEndPoint, ScimConnectorConfiguration conf) {

		ServiceAccessManager accessManager = new ServiceAccessManager(conf);

		String scimBaseUri = accessManager.getBaseUri();

		if (scimBaseUri.isEmpty()) {

			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}

		String uri = new StringBuilder(scimBaseUri).append(SLASH).append(resourceEndPoint).append(SLASH)
				.append(uid.getUidValue()).toString();

		LOGGER.info("The uri for the delete request: {0}", uri);
		HttpDelete httpDelete = buildHttpDelete(uri);
		String responseString = executeRequest(httpDelete);

		if (responseString != null && !responseString.isEmpty()) {
			LOGGER.info("Deletion of resource was succesfull");
		}
	}

	@Override
	public ParserSchemaScim querySchemas(String providerName, String resourceEndPoint,
										 ScimConnectorConfiguration conf) {

		List<String> excludedAttrs = new ArrayList<String>();
		ServiceAccessManager accessManager = new ServiceAccessManager(conf);

		Header authHeader = accessManager.getAuthHeader();
		String scimBaseUri = accessManager.getBaseUri();

		if (authHeader == null || scimBaseUri.isEmpty()) {

			throw new ConnectorException("The data needed for authorization of request to the provider was not found.");
		}

		HttpClient httpClient = initHttpClient(conf);

		String uri = new StringBuilder(scimBaseUri).append(SLASH).append(resourceEndPoint).toString();

		LOGGER.info("Qeury url: {0}", uri);
		HttpGet httpGet = buildHttpGet(uri);
		try (CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(httpGet)) {
			HttpEntity entity = response.getEntity();
			String responseString;
			if (entity != null) {
				responseString = EntityUtils.toString(entity);
			} else {
				responseString = "";
			}

			int statusCode = response.getStatusLine().getStatusCode();
			LOGGER.info("Schema query status code: {0} ", statusCode);
			if (statusCode == 200) {

				if (!responseString.isEmpty()) {

					//LOGGER.warn("The returned response string for the \"schemas/\" endpoint");

					JSONObject jsonObject = new JSONObject(responseString);

					//Normzalize JSON
					jsonObject=normalizeJSON(jsonObject);

					ParserSchemaScim schemaParser = processSchemaResponse(jsonObject);


					excludedAttrs= excludeFromAssembly(excludedAttrs);

					for(String attr: excludedAttrs){
						LOGGER.info("The attribute \"{0}\" will be omitted from the connId object build.", attr);
					}

					return schemaParser;

				} else {

					LOGGER.warn("Response string for the \"schemas/\" endpoint returned empty ");

					String resources[] = { USERS, GROUPS };
					JSONObject responseObject = new JSONObject();
					JSONArray responseArray = new JSONArray();
					for (String resourceName : resources) {
						uri = new StringBuilder(scimBaseUri).append(SLASH).append(resourceEndPoint).append(resourceName)
								.toString();
						LOGGER.info("Additional query url: {0}", uri);

						httpGet = buildHttpGet(uri);

						try (CloseableHttpResponse secondaryResponse = (CloseableHttpResponse) httpClient
								.execute(httpGet)) {

							statusCode = secondaryResponse.getStatusLine().getStatusCode();
							responseString = EntityUtils.toString(secondaryResponse.getEntity());

							if (statusCode == 200 && responseString !=null && !responseString.isEmpty()) {

								/*LOGGER.info(
										"Schema endpoint response: {0}", responseString);
								*/
								JSONObject jsonObject = new JSONObject(responseString);
								//NormalizeJson
								jsonObject=normalizeJSON(jsonObject);
								jsonObject = injectMissingSchemaAttributes(resourceName, jsonObject);

								responseArray.put(jsonObject);

							} else {

								LOGGER.warn(
										"No definition for provided shcemas was found, the connector will switch to default core schema configuration!");
								return null;
							}
						}
						responseObject.put(RESOURCES, responseArray);

					}
					if (responseObject == JSONObject.NULL) {

						return null;

					} else {

						excludedAttrs= excludeFromAssembly(excludedAttrs);

						for(String attr: excludedAttrs){
							LOGGER.info("The attribute \"{0}\" will be omitted from the connId object build.", attr);
						}

						return processSchemaResponse(responseObject);
					}
				}

			} else {

				handleInvalidStatus("while querying for schema. ", responseString, "schema", statusCode);
			}
		} catch (ClientProtocolException e) {
			LOGGER.error(
					"An protocol exception has occurred while in the process of querying the provider Schemas resource object. Possible mismatch in interpretation of the HTTP specification: {0}",
					e.getLocalizedMessage());
			LOGGER.info(
					"An protocol exception has occurred while in the process of querying the provider Schemas resource object. Possible mismatch in interpretation of the HTTP specification: {0}",
					e);
			throw new ConnectorException(
					"An protocol exception has occurred while in the process of querying the provider Schemas resource object. Possible mismatch in interpretation of the HTTP specification",
					e);
		} catch (IOException e) {

			StringBuilder errorBuilder = new StringBuilder(
					"An error has occurred while processing the http response. Occurrence in the process of querying the provider Schemas resource object");

			if ((e instanceof SocketTimeoutException || e instanceof NoRouteToHostException)) {

				errorBuilder.insert(0, "The connection timed out. ");

				throw new OperationTimeoutException(errorBuilder.toString(), e);
			} else {

				LOGGER.error(
						"An error has occurred while processing the http response. Occurrence in the process of querying the provider Schemas resource object: {0}",
						e.getLocalizedMessage());
				LOGGER.info(
						"An error has occurred while processing the http response. Occurrence in the process of querying the provider Schemas resource object: {0}",
						e);

				throw new ConnectorIOException(errorBuilder.toString(), e);
			}
		}

		return null;
	}

	@Override
	public JSONObject injectMissingSchemaAttributes(String resourceName, JSONObject jsonObject) {
		LOGGER.info("Processing trough WORKPLACE missing schema attributes workaround for the resource: \"{0}\"",
				resourceName);
		if (USERS.equals(resourceName)) {

			Map<String, String> missingAttributes = new HashMap<String, String>();
			missingAttributes.put(USERNAME, USERNAME);
                        missingAttributes.put(NAMEFORMATED, NAMEFORMATED);			
			missingAttributes.put(ACTIVE, ACTIVE);
                        missingAttributes.put(SCHEMAS, SCHEMAS);
                        missingAttributes.put(ADDRESSESATTRIBUTESFORMATTED, ADDRESSESATTRIBUTESFORMATTED);
                        missingAttributes.put(ADDRESSESATTRIBUTESPRIMARY, ADDRESSESATTRIBUTESPRIMARY);
                        missingAttributes.put(EXTENSIONSTARTTERMDATESSTARTDATE, EXTENSIONSTARTTERMDATESSTARTDATE);
                        missingAttributes.put(EXTENSIONSTARTTERMDATESENDDATE, EXTENSIONSTARTTERMDATESENDDATE);
                        missingAttributes.put(EXTENSIONENTERPRISEDIVISION, EXTENSIONENTERPRISEDIVISION);
                        missingAttributes.put(EXTENSIONENTERPRISEMANAGER, EXTENSIONENTERPRISEMANAGER);
                        missingAttributes.put(EXTENSIONENTERPRISEORGANIZATION, EXTENSIONENTERPRISEORGANIZATION);
                        missingAttributes.put(EXTENSIONENTERPRISEDEPARTMENT, EXTENSIONENTERPRISEDEPARTMENT);
                        missingAttributes.put(EXTENSIONENTERPRISECOSTCENTER, EXTENSIONENTERPRISECOSTCENTER);
                        missingAttributes.put(EXTENSIONENTERPRISEEMPLOYEENUMBER, EXTENSIONENTERPRISEEMPLOYEENUMBER);
                        missingAttributes.put(EXTERNALID, EXTERNALID);

			if (jsonObject.has(ATTRIBUTES)) {

				JSONArray attributesArray = new JSONArray();

				attributesArray = jsonObject.getJSONArray(ATTRIBUTES);
				for (int indexValue = 0; indexValue < attributesArray.length(); indexValue++) {
					JSONObject subAttributes = attributesArray.getJSONObject(indexValue);					

						if (USERNAME.equals(subAttributes.get(USERNAME))) {

							missingAttributes.remove(USERNAME);
						} else if (NAMEFORMATED.equals(subAttributes.get(NAMEFORMATED))) {

							missingAttributes.remove(NAMEFORMATED);
						} else if (ACTIVE.equals(subAttributes.get(ACTIVE))) {

							missingAttributes.remove(ACTIVE);
						} else if (SCHEMAS.equals(subAttributes.get(SCHEMAS))) {

							missingAttributes.remove(SCHEMAS);
						} else if (ADDRESSESATTRIBUTESFORMATTED.equals(subAttributes.get(ADDRESSESATTRIBUTESFORMATTED))) {

							missingAttributes.remove(ADDRESSESATTRIBUTESFORMATTED);
						} else if (ADDRESSESATTRIBUTESPRIMARY.equals(subAttributes.get(ADDRESSESATTRIBUTESPRIMARY))) {

							missingAttributes.remove(ADDRESSESATTRIBUTESPRIMARY);
						} else if (EXTENSIONSTARTTERMDATESSTARTDATE.equals(subAttributes.get(EXTENSIONSTARTTERMDATESSTARTDATE))) {

							missingAttributes.remove(EXTENSIONSTARTTERMDATESSTARTDATE);
						} else if (EXTENSIONSTARTTERMDATESENDDATE.equals(subAttributes.get(EXTENSIONSTARTTERMDATESENDDATE))) {

							missingAttributes.remove(EXTENSIONSTARTTERMDATESENDDATE);
						} else if (EXTENSIONENTERPRISEDIVISION.equals(subAttributes.get(EXTENSIONENTERPRISEDIVISION))) {

							missingAttributes.remove(EXTENSIONENTERPRISEDIVISION);
						} else if (EXTENSIONENTERPRISEMANAGER.equals(subAttributes.get(EXTENSIONENTERPRISEMANAGER))) {

							missingAttributes.remove(EXTENSIONENTERPRISEMANAGER);
						} else if (EXTENSIONENTERPRISEORGANIZATION.equals(subAttributes.get(EXTENSIONENTERPRISEORGANIZATION))) {

							missingAttributes.remove(EXTENSIONENTERPRISEORGANIZATION);
						} else if (EXTENSIONENTERPRISEDEPARTMENT.equals(subAttributes.get(EXTENSIONENTERPRISEDEPARTMENT))) {

							missingAttributes.remove(EXTENSIONENTERPRISEDEPARTMENT);
						} else if (EXTENSIONENTERPRISECOSTCENTER.equals(subAttributes.get(EXTENSIONENTERPRISECOSTCENTER))) {

							missingAttributes.remove(EXTENSIONENTERPRISECOSTCENTER);
						} else if (EXTENSIONENTERPRISEEMPLOYEENUMBER.equals(subAttributes.get(EXTENSIONENTERPRISEEMPLOYEENUMBER))) {

							missingAttributes.remove(EXTENSIONENTERPRISEEMPLOYEENUMBER);
						} else if (EXTERNALID.equals(subAttributes.get(EXTERNALID))) {

							missingAttributes.remove(EXTERNALID);
						} 
					}
				

				for (String missingAttributeName : missingAttributes.keySet()) {

					LOGGER.info("Building schema definition for the attribute: \"{0}\"", missingAttributeName);

					if (USERNAME.equals(missingAttributeName)) {
						JSONObject userName = new JSONObject();

						userName.put(SCHEMA, SCHEMAVALUE);
						userName.put(NAME, USERNAME);
						userName.put(READONLY, false);
						userName.put(TYPE, STRING);
						userName.put(REQUIRED, false);
						userName.put(CASEEXSACT, false);

						attributesArray.put(userName);

					} else if (ACTIVE.equals(missingAttributeName)) {
						JSONObject active = new JSONObject();

						active.put(SCHEMA, SCHEMAVALUE);
						active.put(NAME, ACTIVE);
						active.put(READONLY, false);
						active.put(TYPE, "boolean");
						active.put(REQUIRED, true);
						active.put(CASEEXSACT, false);

						attributesArray.put(active);

					}  else if (NAMEFORMATED.equals(missingAttributeName)) {
						JSONObject displayName = new JSONObject();

						displayName.put(SCHEMA, SCHEMAVALUE);
						displayName.put(NAME, NAMEFORMATED);
						displayName.put(READONLY, false);
						displayName.put(TYPE, STRING);
						displayName.put(REQUIRED, true);
						displayName.put(CASEEXSACT, true);

						attributesArray.put(displayName);

					} else if (SCHEMAS.equals(missingAttributeName)) {
						JSONObject schemas = new JSONObject();
						JSONArray subAttributeArray = new JSONArray();
                                                
						JSONObject valueBlank = new JSONObject();

						schemas.put(SCHEMA, SCHEMAVALUE);
						schemas.put(NAME, SCHEMAS);
						schemas.put(READONLY, false);
						schemas.put(TYPE, "complex");
						schemas.put(MULTIVALUED, true);
						schemas.put(REQUIRED, false);
						schemas.put(CASEEXSACT, false);

						valueBlank.put(NAME, "blank");
						valueBlank.put(READONLY, true);
						valueBlank.put(REQUIRED, false);
						valueBlank.put(MULTIVALUED, false);

						subAttributeArray.put(valueBlank);

						schemas.put(SUBATTRIBUTES, subAttributeArray);

						attributesArray.put(schemas);
					} else if (ADDRESSESATTRIBUTESFORMATTED.equals(missingAttributeName)) {
						JSONObject displayName = new JSONObject();

						displayName.put(SCHEMA, SCHEMAVALUE);
						displayName.put(NAME, ADDRESSESATTRIBUTESFORMATTED);
						displayName.put(READONLY, false);
						displayName.put(TYPE, STRING);
						displayName.put(REQUIRED, false);
						displayName.put(CASEEXSACT, true);

						attributesArray.put(displayName);

					} else if (ADDRESSESATTRIBUTESPRIMARY.equals(missingAttributeName)) {
						JSONObject putValue = new JSONObject();

						putValue.put(SCHEMA, SCHEMAVALUE);
						putValue.put(NAME, ADDRESSESATTRIBUTESPRIMARY);
						putValue.put(READONLY, false);
						putValue.put(TYPE, "boolean");
						putValue.put(REQUIRED, false);
						putValue.put(CASEEXSACT, true);

						attributesArray.put(putValue);

					} else if (EXTENSIONSTARTTERMDATESSTARTDATE.equals(missingAttributeName)) {
						JSONObject putValue = new JSONObject();

						putValue.put(SCHEMA, SCHEMAVALUE);
						putValue.put(NAME, EXTENSIONSTARTTERMDATESSTARTDATE);
						putValue.put(READONLY, false);
						putValue.put(TYPE, "long");
						putValue.put(REQUIRED, false);
						putValue.put(CASEEXSACT, false);

						attributesArray.put(putValue);

					} else if (EXTENSIONSTARTTERMDATESENDDATE.equals(missingAttributeName)) {
						JSONObject putValue = new JSONObject();

						putValue.put(SCHEMA, SCHEMAVALUE);
						putValue.put(NAME, EXTENSIONSTARTTERMDATESENDDATE);
						putValue.put(READONLY, false);
						putValue.put(TYPE, "long");
						putValue.put(REQUIRED, false);
						putValue.put(CASEEXSACT, false);

						attributesArray.put(putValue);

					} else if (EXTENSIONENTERPRISEDIVISION.equals(missingAttributeName)) {
						JSONObject putValue = new JSONObject();

						putValue.put(SCHEMA, SCHEMAVALUE);
						putValue.put(NAME, EXTENSIONENTERPRISEDIVISION);
						putValue.put(READONLY, false);
						putValue.put(TYPE, STRING);
						putValue.put(REQUIRED, false);
						putValue.put(CASEEXSACT, true);

						attributesArray.put(putValue);

					} else if (EXTENSIONENTERPRISEMANAGER.equals(missingAttributeName)) {
						JSONObject putValue = new JSONObject();

						putValue.put(SCHEMA, SCHEMAVALUE);
						putValue.put(NAME, EXTENSIONENTERPRISEMANAGER);
						putValue.put(READONLY, false);
						putValue.put(TYPE, "long");
						putValue.put(REQUIRED, false);
						putValue.put(CASEEXSACT, false);

						attributesArray.put(putValue);

					} else if (EXTENSIONENTERPRISEORGANIZATION.equals(missingAttributeName)) {
						JSONObject putValue = new JSONObject();

						putValue.put(SCHEMA, SCHEMAVALUE);
						putValue.put(NAME, EXTENSIONENTERPRISEORGANIZATION);
						putValue.put(READONLY, false);
						putValue.put(TYPE, STRING);
						putValue.put(REQUIRED, false);
						putValue.put(CASEEXSACT, true);

						attributesArray.put(putValue);

					} else if (EXTENSIONENTERPRISEDEPARTMENT.equals(missingAttributeName)) {
						JSONObject putValue = new JSONObject();

						putValue.put(SCHEMA, SCHEMAVALUE);
						putValue.put(NAME, EXTENSIONENTERPRISEDEPARTMENT);
						putValue.put(READONLY, false);
						putValue.put(TYPE, STRING);
						putValue.put(REQUIRED, false);
						putValue.put(CASEEXSACT, true);

						attributesArray.put(putValue);

					} else if (EXTENSIONENTERPRISECOSTCENTER.equals(missingAttributeName)) {
						JSONObject putValue = new JSONObject();

						putValue.put(SCHEMA, SCHEMAVALUE);
						putValue.put(NAME, EXTENSIONENTERPRISECOSTCENTER);
						putValue.put(READONLY, false);
						putValue.put(TYPE, STRING);
						putValue.put(REQUIRED, false);
						putValue.put(CASEEXSACT, true);

						attributesArray.put(putValue);

					} else if (EXTENSIONENTERPRISEEMPLOYEENUMBER.equals(missingAttributeName)) {
						JSONObject putValue = new JSONObject();

						putValue.put(SCHEMA, SCHEMAVALUE);
						putValue.put(NAME, EXTENSIONENTERPRISEEMPLOYEENUMBER);
						putValue.put(READONLY, false);
						putValue.put(TYPE, STRING);
						putValue.put(REQUIRED, false);
						putValue.put(CASEEXSACT, false);

						attributesArray.put(putValue);

					} else if (EXTERNALID.equals(missingAttributeName)) {
						JSONObject putValue = new JSONObject();

						putValue.put(SCHEMA, SCHEMAVALUE);
						putValue.put(NAME, EXTERNALID);
						putValue.put(READONLY, false);
						putValue.put(TYPE, STRING);
						putValue.put(REQUIRED, true);
						putValue.put(CASEEXSACT, false);

						attributesArray.put(putValue);

					} 
                                       

				}

				jsonObject.put(ATTRIBUTES, attributesArray);
			}

		}
		return jsonObject;
	}

	@Override
	public ParserSchemaScim processSchemaResponse(JSONObject responseObject) {

		// LOGGER.info("The resources json representation: {0}",
		// responseObject.toString(1));
		ParserSchemaScim scimParser = new ParserSchemaScim();
		for (int i = 0; i < responseObject.getJSONArray(RESOURCES).length(); i++) {
			JSONObject minResourceJson = new JSONObject();
			minResourceJson = responseObject.getJSONArray(RESOURCES).getJSONObject(i);

			if (minResourceJson.has("endpoint")) {
				scimParser.parseSchema(minResourceJson, this);

			} else {
				LOGGER.error("No endpoint identifier present in fetched object: {0}", minResourceJson);

				throw new ConnectorException(
						"No endpoint identifier present in fetched object while processing queuery result");
			}
		}
		return scimParser;

	}

	@Override
	public Map<String, Map<String, Object>> parseSchemaAttribute(JSONObject attribute,
			Map<String, Map<String, Object>> attributeMap, ParserSchemaScim parser) {

		String attributeName = null;
		Boolean isComplex = false;
		Boolean isMultiValued = false;
		Boolean hasSubAttributes = false;
		String nameFromDictionary = "";
		Map<String, Object> attributeObjects = new HashMap<String, Object>();
		Map<String, Object> subAttributeMap = new HashMap<String, Object>();

		List<String> dictionary = populateDictionary(WorkaroundFlags.PARSERFLAG);
		List<String> excludedAttributes = defineExcludedAttributes();
		for (int position = 0; position < dictionary.size(); position++) {
			nameFromDictionary = dictionary.get(position);

			if (attribute.has(nameFromDictionary)) {

				hasSubAttributes = true;
				break;
			}

		}
		if (hasSubAttributes) {

			boolean hasTypeValues = false;
			JSONArray subAttributes = new JSONArray();
			subAttributes = (JSONArray) attribute.get(nameFromDictionary);
			if (attributeName == null) {
				for (String subAttributeNameKeys : attribute.keySet()) {
					if (NAME.equals(subAttributeNameKeys)) {
						attributeName = attribute.get(subAttributeNameKeys).toString();

						if (attributeName.contains(FORBIDENSEPPARATOR)) {
							attributeName = attributeName.replace(FORBIDENSEPPARATOR, SEPPARATOR);
						}

						break;
					}
				}
			}

			if (!excludedAttributes.contains(attributeName)) {

				for (String nameKey : attribute.keySet()) {
					if (MULTIVALUED.equals(nameKey)) {
						isMultiValued = (Boolean) attribute.get(nameKey);
						break;
					}
				}

				for (int i = 0; i < subAttributes.length(); i++) {
					JSONObject subAttribute = new JSONObject();
					subAttribute = subAttributes.getJSONObject(i);
					subAttributeMap = parser.parseSubAttribute(subAttribute, subAttributeMap);
				}
				for (String typeKey : subAttributeMap.keySet()) {
					if (TYPE.equals(typeKey)) {
						hasTypeValues = true;
						break;
					}
				}

				if (hasTypeValues) {
					Map<String, Object> typeObject = new HashMap<String, Object>();
					typeObject = (HashMap<String, Object>) subAttributeMap.get(TYPE);
					if (typeObject.containsKey(CANONICALVALUES) || typeObject.containsKey(REFERENCETYPES)) {
						JSONArray referenceValues = new JSONArray();
						if (typeObject.containsKey(CANONICALVALUES)) {
							referenceValues = (JSONArray) typeObject.get(CANONICALVALUES);
						} else {
							referenceValues = (JSONArray) typeObject.get(REFERENCETYPES);
						}

						for (int position = 0; position < referenceValues.length(); position++) {

							Map<String, Object> processedParameters = translateReferenceValues(attributeMap,
									referenceValues, subAttributeMap, position, attributeName);

							for (String parameterName : processedParameters.keySet()) {
								if (ISCOMPLEX.equals(parameterName)) {

									isComplex = (Boolean) processedParameters.get(parameterName);

								} else {
									attributeMap = (Map<String, Map<String, Object>>) processedParameters
											.get(parameterName);
								}

							}

						}
					} else {
						// default set of canonical values.

						List<String> defaultReferenceTypeValues = new ArrayList<String>();
						defaultReferenceTypeValues.add("User");
						defaultReferenceTypeValues.add("Group");

						defaultReferenceTypeValues.add("external");
						defaultReferenceTypeValues.add(URI);

						for (String subAttributeKeyNames : subAttributeMap.keySet()) {
							if (!TYPE.equals(subAttributeKeyNames)) {
								for (String defaultTypeReferenceValues : defaultReferenceTypeValues) {
									StringBuilder complexAttrName = new StringBuilder(attributeName);
									complexAttrName.append(DOT).append(defaultTypeReferenceValues);
									attributeMap.put(
											complexAttrName.append(DOT).append(subAttributeKeyNames).toString(),
											(HashMap<String, Object>) subAttributeMap.get(subAttributeKeyNames));
									isComplex = true;
								}
							}
						}
					}
				} else {

					if (!isMultiValued) {
						for (String subAttributeKeyNames : subAttributeMap.keySet()) {
							StringBuilder complexAttrName = new StringBuilder(attributeName);
							attributeMap.put(complexAttrName.append(DOT).append(subAttributeKeyNames).toString(),
									(HashMap<String, Object>) subAttributeMap.get(subAttributeKeyNames));
							isComplex = true;
						}
					} else {
						for (String subAttributeKeyNames : subAttributeMap.keySet()) {
							StringBuilder complexAttrName = new StringBuilder(attributeName);

							Map<String, Object> subattributeKeyMap = (HashMap<String, Object>) subAttributeMap
									.get(subAttributeKeyNames);

							for (String attributeProperty : subattributeKeyMap.keySet()) {

								if (MULTIVALUED.equals(attributeProperty)) {
									subattributeKeyMap.put(MULTIVALUED, true);
								}
							}
							attributeMap.put(complexAttrName.append(DOT).append(DEFAULT).append(DOT)
									.append(subAttributeKeyNames).toString(), subattributeKeyMap);
							isComplex = true;
						}
					}
				}
			}
		} else {

			for (String attributeNameKeys : attribute.keySet()) {
				if (!excludedAttributes.contains(attributeName)) {
					if (NAME.equals(attributeNameKeys)) {
						attributeName = attribute.get(attributeNameKeys).toString();
						if (attributeName.contains(FORBIDENSEPPARATOR)) {
							attributeName = attributeName.replace(FORBIDENSEPPARATOR, SEPPARATOR);
						}
					} else {
						attributeObjects.put(attributeNameKeys, attribute.get(attributeNameKeys));
					}
				} else {
					if (!attributeObjects.isEmpty()) {

						attributeObjects.clear();
					}
				}
			}
		}
		if (!isComplex) {
			if (!attributeObjects.isEmpty()) {
				attributeMap.put(attributeName, attributeObjects);
			}
		}
		return attributeMap;
	}

	@Override
	public List<Map<String, Map<String, Object>>> getAttributeMapList(
			List<Map<String, Map<String, Object>>> attributeMapList) {
                LOGGER.info("Output preprocessing getAttributeMapList {0}", attributeMapList);
		return attributeMapList;
	}

	@Override
	public Map<String, Object> translateReferenceValues(Map<String, Map<String, Object>> attributeMap,
			JSONArray referenceValues, Map<String, Object> subAttributeMap, int position, String attributeName) {

		Boolean isComplex = null;
		Map<String, Object> processedParameters = new HashMap<String, Object>();

		String sringReferenceValue = (String) referenceValues.get(position);

		for (String subAttributeKeyNames : subAttributeMap.keySet()) {
			if (!TYPE.equals(subAttributeKeyNames)) {

				StringBuilder complexAttrName = new StringBuilder(attributeName);
				attributeMap.put(complexAttrName.append(DOT).append(sringReferenceValue).append(DOT)
						.append(subAttributeKeyNames).toString(),
						(HashMap<String, Object>) subAttributeMap.get(subAttributeKeyNames));
				isComplex = true;

			}
		}
		if (isComplex != null) {
			processedParameters.put(ISCOMPLEX, isComplex);
		}
		processedParameters.put("attributeMap", attributeMap);

		return processedParameters;
	}

	@Override
	public List<String> defineExcludedAttributes() {
            	List<String> excludedList = new ArrayList<String>();
		excludedList.add("roles");
		return excludedList;
	}

	@Override
	public Set<Attribute> addAttributesToInject(Set<Attribute> injectedAttributeSet) {
		Attribute schemaAttribute = AttributeBuilder.build("schemas.default.blank", SCHEMAVALUE);
		Attribute enterpriceSchemaAttribute = AttributeBuilder.build("schemas.default.blank", ENTERPRISEVALUE);

		injectedAttributeSet.add(schemaAttribute);
		injectedAttributeSet.add(enterpriceSchemaAttribute);

		return injectedAttributeSet;
	}

	@Override
	public Uid groupUpdateProcedure(Integer statusCode, JSONObject jsonObject, String uri, Header authHeader,
			ScimConnectorConfiguration conf) {
		return null;
	}

	@Override
	public ConnectorObject buildConnectorObject(JSONObject resourceJsonObject, String resourceEndPoint)
			throws ConnectorException {

		List<String> excludedAttributes = new ArrayList<String>();

		LOGGER.info("Building the connector object from provided json");

		if (resourceJsonObject == null) {
			LOGGER.error(
					"Empty json object was passed from data provider. Error ocourance while building connector object");
			throw new ConnectorException(
					"Empty json object was passed from data provider. Error ocourance while building connector object");
		}

		ConnectorObjectBuilder cob = new ConnectorObjectBuilder();
                //FIX
		String uid = String.valueOf(resourceJsonObject.getLong(ID));
		cob.setUid(uid);
		excludedAttributes.add(ID);
		if (USERS.equals(resourceEndPoint)) {
			cob.setName(resourceJsonObject.getString(USERNAME));
			excludedAttributes.add(USERNAME);

			JSONArray groups = resourceJsonObject.getJSONArray("groups");
			Collection<String> groupsIds = new ArrayList<>();
			for (int i = 0; i < groups.length(); i++){
				String gid = String.valueOf(groups.get(i));
				groupsIds.add(gid);
			}
			cob.addAttribute("groups", groupsIds);
			resourceJsonObject.remove("groups");
		} else if (GROUPS.equals(resourceEndPoint)) {
			cob.setName(resourceJsonObject.getString("name"));
			excludedAttributes.add("name");
			cob.setObjectClass(ObjectClass.GROUP);
		} else {
			cob.setName(resourceJsonObject.getString(DISPLAYNAME));
			excludedAttributes.add(DISPLAYNAME);
			ObjectClass objectClass = new ObjectClass(resourceEndPoint);
			cob.setObjectClass(objectClass);

		}
		for (String key : resourceJsonObject.keySet()) {
			Object attribute = resourceJsonObject.get(key);

			excludedAttributes = excludeFromAssembly(excludedAttributes);

			if (excludedAttributes.contains(key)) {
				
				//LOGGER.warn("The attribute \"{0}\" was omitted from the connId object build.", key);
			
			} else

			if (attribute instanceof JSONArray) {

				JSONArray attributeArray = (JSONArray) attribute;

				Map<String, Collection<Object>> multivaluedAttributeMap = new HashMap<String, Collection<Object>>();
				Collection<Object> attributeValues = new ArrayList<Object>();

				for (Object singleAttribute : attributeArray) {
					StringBuilder objectNameBilder = new StringBuilder(key);
					String objectKeyName = "";
					if (singleAttribute instanceof JSONObject) {

						for (String singleSubAttribute : ((JSONObject) singleAttribute).keySet()) {
							if (TYPE.equals(singleSubAttribute)) {
								objectKeyName = objectNameBilder.append(DOT)
										.append(((JSONObject) singleAttribute).get(singleSubAttribute)).toString();
								objectNameBilder.delete(0, objectNameBilder.length());
								break;
							}
						}

						for (String singleSubAttribute : ((JSONObject) singleAttribute).keySet()) {
							Object sAttributeValue;
							if (((JSONObject) singleAttribute).isNull(singleSubAttribute)) {
								sAttributeValue = null;
							} else {

								sAttributeValue = ((JSONObject) singleAttribute).get(singleSubAttribute);
							}

							if (TYPE.equals(singleSubAttribute)) {
							} else {

								if (!"".equals(objectKeyName)) {
									objectNameBilder = objectNameBilder.append(objectKeyName).append(DOT)
											.append(singleSubAttribute);
								} else {
									objectKeyName = objectNameBilder.append(DOT).append(DEFAULT).toString();
									objectNameBilder = objectNameBilder.append(DOT).append(singleSubAttribute);
								}

								if (attributeValues.isEmpty()) {

									attributeValues.add(sAttributeValue);
									multivaluedAttributeMap.put(objectNameBilder.toString(), attributeValues);
								} else {
									if (multivaluedAttributeMap.containsKey(objectNameBilder.toString())) {
										attributeValues = multivaluedAttributeMap.get(objectNameBilder.toString());
										attributeValues.add(sAttributeValue);
									} else {
										Collection<Object> newAttributeValues = new ArrayList<Object>();
										newAttributeValues.add(sAttributeValue);
										multivaluedAttributeMap.put(objectNameBilder.toString(), newAttributeValues);
									}

								}
								objectNameBilder.delete(0, objectNameBilder.length());

							}
						}
					} else {
						objectKeyName = objectNameBilder.append(DOT).append(singleAttribute.toString()).toString();
						cob.addAttribute(objectKeyName, singleAttribute);
					}
				}

				if (!multivaluedAttributeMap.isEmpty()) {
					for (String attributeName : multivaluedAttributeMap.keySet()) {
						cob.addAttribute(attributeName, multivaluedAttributeMap.get(attributeName));
					}

				}

			} else if (attribute instanceof JSONObject) {
				for (String s : ((JSONObject) attribute).keySet()) {
					Object attributeValue;
					if (key.contains(FORBIDENSEPPARATOR)) {
						key = key.replace(FORBIDENSEPPARATOR, SEPPARATOR);
					}

					if (((JSONObject) attribute).isNull(s)) {

						attributeValue = null;

					} else {

						attributeValue = ((JSONObject) attribute).get(s);

					}

					StringBuilder objectNameBilder = new StringBuilder(key);
					cob.addAttribute(objectNameBilder.append(DOT).append(s).toString(), attributeValue);
				}

			} else {

				if (ACTIVE.equals(key)) {
					cob.addAttribute(OperationalAttributes.ENABLE_NAME, resourceJsonObject.get(key));
				} else {

					if (!resourceJsonObject.isNull(key)) {

						cob.addAttribute(key, resourceJsonObject.get(key));
					} else {
						Object value = null;
						cob.addAttribute(key, value);

					}
				}
			}
		}
		ConnectorObject finalConnectorObject = cob.build();
		// LOGGER.info("The connector object returned from the processed json: {0}", finalConnectorObject);
		return finalConnectorObject;

	}

	@Override
	public List<String> excludeFromAssembly(List<String> excludedAttributes) {

		excludedAttributes.add(META);
		excludedAttributes.add("schemas");
                excludedAttributes.add("urn:scim:schemas:extension:facebook:auth_method:1.0");
                excludedAttributes.add("urn:scim:schemas:extension:facebook:accountstatusdetails:1.0");
                excludedAttributes.add("roles");                
		//excludedAttributes.add("urn:scim:schemas:extension:enterprise:1.0"); //TODO check this extension attribute
		return excludedAttributes;
	}

	@Override
	public Set<Attribute> attributeInjection(Set<Attribute> injectedAttributeSet, JSONObject loginJson) {
		return injectedAttributeSet;
	}

	@Override
	public StringBuilder processContainsAllValuesFilter(String p, ContainsAllValuesFilter filter,
			FilterHandler handler) {
		StringBuilder preprocessedFilter = null;
		preprocessedFilter = handler.processArrayQ(filter, p);
		return preprocessedFilter;
	}

	@Override
	public ObjectClassInfoBuilder schemaBuilder(String attributeName, Map<String, Map<String, Object>> attributeMap,
			ObjectClassInfoBuilder builder, SchemaObjectBuilderGeneric schemaBuilder) {

		AttributeInfoBuilder infoBuilder = new AttributeInfoBuilder(attributeName);
		Boolean containsDictionaryValue = false;
		Map<String, Object> caseHandlingMap = new HashMap<String, Object>();

		List<String> dictionary = populateDictionary(WorkaroundFlags.BUILDERFLAG);

		if (dictionary.contains(attributeName)) {
			containsDictionaryValue = true;
		}

		if (!containsDictionaryValue) {
			dictionary.clear();
			Map<String, Object> schemaSubPropertysMap = new HashMap<String, Object>();
			schemaSubPropertysMap = attributeMap.get(attributeName);

			for (String subPropertyName : schemaSubPropertysMap.keySet()) {
				containsDictionaryValue = false;
				dictionary = populateDictionary(WorkaroundFlags.PARSERFLAG);
				if (dictionary.contains(subPropertyName)) {
					containsDictionaryValue = true;
				}

				if (containsDictionaryValue) {
					// TODO check positive cases
					infoBuilder = new AttributeInfoBuilder(attributeName);
					JSONArray jsonArray = new JSONArray();
                LOGGER.info("The sub property name: {0}", subPropertyName);
					break;
				} else {

					if ("type".equals(subPropertyName)) {

						if ("string".equals(schemaSubPropertysMap.get(subPropertyName).toString())) {

							caseHandlingMap.put("type", "string");

						} else if ("boolean".equals(schemaSubPropertysMap.get(subPropertyName).toString())) {

							caseHandlingMap.put("type", "bool");
							infoBuilder.setType(Boolean.class);
						}
					} else if ("caseExact".equals(subPropertyName)) {

						caseHandlingMap.put("caseExact", (Boolean) schemaSubPropertysMap.get(subPropertyName));
					}

					infoBuilder = schemaBuilder.subPropertiesChecker(infoBuilder, schemaSubPropertysMap,
							subPropertyName);
					infoBuilder = schemaObjectParametersInjection(infoBuilder, attributeName);

				}

			}
			if (!caseHandlingMap.isEmpty()) {
				if (caseHandlingMap.containsKey("type")) {
					if ("string".equals(caseHandlingMap.get("type"))) {
						infoBuilder.setType(String.class);
						if (caseHandlingMap.containsKey("caseExact")) {
							if (!(Boolean) caseHandlingMap.get("caseExact")) {
								infoBuilder.setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE);
							}
						}
					} else if ("boolean".equals(caseHandlingMap.get("type"))) {
						infoBuilder.setType(Boolean.class);
					}

				}

			}

			builder.addAttributeInfo(infoBuilder.build());
		} else {
			builder = schemaObjectInjection(builder, attributeName, infoBuilder);
		}
		return builder;
	}

	@Override
	public ObjectClassInfoBuilder schemaObjectInjection(ObjectClassInfoBuilder builder, String attributeName,
			AttributeInfoBuilder infoBuilder) {

		builder.addAttributeInfo(OperationalAttributeInfos.ENABLE);
		builder.addAttributeInfo(OperationalAttributeInfos.PASSWORD);

		return builder;
	}

	@Override
	public AttributeInfoBuilder schemaObjectParametersInjection(AttributeInfoBuilder infoBuilder,
			String attributeName) {
		return infoBuilder;
	}

	@Override
	public List<String> populateDictionary(WorkaroundFlags flag) {

		List<String> dictionary = new ArrayList<String>();

		if (WorkaroundFlags.PARSERFLAG.getValue().equals(flag.getValue())) {
			dictionary.add(SUBATTRIBUTES);
		} else if (WorkaroundFlags.BUILDERFLAG.getValue().equals(flag.getValue())) {

			dictionary.add(ACTIVE);
		} else {

			LOGGER.warn("No such flag defined: {0}", flag);
		}
		return dictionary;

	}

	@Override
	public Boolean checkFilter(Filter filter, String endpointName) {
		LOGGER.info("Check filter standard");
		return false;
	}

	/**
	 * Called when the query is evaluated as an filter not containing an uid
	 * type attribute.
	 * 
	 * @param query
	 *            The provided filter query.
	 * @param queryUriSnippet
	 *            A part of the query uri which will build a larger query.
	 */

	private String qIsFilter(Filter query, StringBuilder queryUriSnippet, String providerName,
			String resourceEndPoint) {

		char prefixChar;
		StringBuilder filterSnippet = new StringBuilder();
		if (queryUriSnippet.toString().isEmpty()) {
			prefixChar = QUERYCHAR;

		} else {

			prefixChar = QUERYDELIMITER;
		}


		StringBuilder providerDotEndpoint = new StringBuilder(resourceEndPoint).append(DOT).append(providerName);


			filterSnippet = query.accept(new FilterHandler(), providerDotEndpoint.toString());

		queryUriSnippet.append(prefixChar).append("filter=").append(filterSnippet.toString());

		return queryUriSnippet.toString();
	}

	protected HttpPost buildHttpPost(String uri, JSONObject jsonBody)
			throws UnsupportedEncodingException, JSONException {

		HttpPost httpPost = new HttpPost(uri);
		httpPost.addHeader(authHeader);
		httpPost.addHeader(PRETTYPRINTHEADER);

		HttpEntity entity = new ByteArrayEntity(jsonBody.toString().getBytes("UTF-8"));
		httpPost.setEntity(entity);
		httpPost.setHeader("Content-Type", CONTENTTYPE);

		return httpPost;
	}

	protected HttpGet buildHttpGet(String uri) {

		HttpGet httpGet = new HttpGet(uri);
		httpGet.addHeader(authHeader);
		httpGet.addHeader(PRETTYPRINTHEADER);

		return httpGet;
	}

	protected HttpDelete buildHttpDelete(String uri) {

		HttpDelete httpDelete = new HttpDelete(uri);
		httpDelete.addHeader(authHeader);
		httpDelete.addHeader(PRETTYPRINTHEADER);
		return httpDelete;
	}

	public void handleInvalidStatus(String errorPitch, String responseString, String situation, int statusCode)
			throws ParseException, IOException {

		String error = ErrorHandler.onNoSuccess(responseString, statusCode, situation);
		StringBuilder errorString = new StringBuilder(errorPitch).append(error);
		switch (statusCode) {
		case 400:
			handleBadRequest(error);
			break;
		case 401:
			errorString.insert(0, "Unauthorized ");
			throw new InvalidCredentialException(errorString.toString());
		case 404:
			LOGGER.warn("Resource not found or resource was already deleted");
			break;
		case 409:
			errorString.insert(0, "Conflict ");
			throw new AlreadyExistsException(errorString.toString());
		case 500:
			errorString.insert(0, "Provider server error ");
			throw new ConnectorException(errorString.toString());
		default:
			LOGGER.warn(error);
			break;
		}
	}

	public void handleBadRequest(String error) {

		throw new ConnectorException(error);
	}

	protected HttpClient initHttpClient(ScimConnectorConfiguration conf) {
		HttpClientBuilder httpClientBulder = HttpClientBuilder.create();

		if (StringUtil.isNotEmpty(conf.getProxyUrl())) {
			HttpHost proxy = new HttpHost(conf.getProxyUrl(), conf.getProxyPortNumber());
			DefaultProxyRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxy);
			httpClientBulder.setRoutePlanner(routePlanner);
		}

		HttpClient httpClient = httpClientBulder.build();

		return httpClient;
	}

    private HttpPut buildHttpPut(String uri, JSONObject jsonBody) throws UnsupportedEncodingException {
		HttpPut httpPut = new HttpPut(uri);
		httpPut.addHeader(authHeader);
		httpPut.addHeader(PRETTYPRINTHEADER);

		HttpEntity entity = new ByteArrayEntity(jsonBody.toString().getBytes("UTF-8"));
		httpPut.setEntity(entity);
		httpPut.setHeader("Content-Type", CONTENTTYPE);

		return httpPut;
    }


    private String getCommunityId(){
        String uri = GRAPH_API_BASE_URI + SLASH + "community";

        LOGGER.info("getCommunityId: {0}", uri);
        HttpGet httpGet = buildHttpGet(uri);

        String responseString = executeRequest(httpGet);

        if (responseString != null && !responseString.isEmpty()) {
            JSONObject jsonObject = new JSONObject(responseString);
            if(jsonObject.has("id")){
                return jsonObject.getString("id");
            }
        }

        LOGGER.error("Failed getCommunityId: {0}", uri);
        return null;
    }


	private JSONObject getGroupsPage(String page){
		String uri = GRAPH_API_BASE_URI + SLASH + communityId + SLASH + "groups";

		if(!page.equals("")){
			uri = uri + "?after=" + page;
		}

		LOGGER.info("getGroups: {0}", uri);
		HttpGet httpGet = buildHttpGet(uri);

		String responseString = executeRequest(httpGet);

		if (responseString != null && !responseString.isEmpty()) {
			return new JSONObject(responseString);
		}

		LOGGER.error("Failed getGroups: {0}", uri);
		return null;
	}

	private JSONObject getGroup(String gid){
		String uri = GRAPH_API_BASE_URI + SLASH + gid;

		LOGGER.info("getGroup: {0}", uri);
		HttpGet httpGet = buildHttpGet(uri);
		String responseString = executeRequest(httpGet);

		if (responseString != null && !responseString.isEmpty()) {
			return new JSONObject(responseString);
		}

		LOGGER.error("Failed getGroup: {0}", uri);
		return null;
	}

    private JSONObject getUserGroupsPage(String uid, String page){
		String uri = GRAPH_API_BASE_URI + SLASH + uid + SLASH + "groups";

		if(!page.equals("")){
			uri = uri + "?after=" + page;
		}

		LOGGER.info("getUserGroups: {0}", uri);
		HttpGet httpGet = buildHttpGet(uri);

		String responseString = executeRequest(httpGet);

		if (responseString != null && !responseString.isEmpty()) {
			return new JSONObject(responseString);
		}

		LOGGER.error("Failed getUserGroups: {0}", uri);
		return null;
	}

	private JSONObject getUserGroups(String uid){
		JSONObject result = getUserGroupsPage(uid, "");
		JSONArray resultData = result.getJSONArray("data");

		String nextPage = getNextPage(result);
		while(nextPage != null){
			result = getUserGroupsPage(uid, nextPage);
			nextPage = getNextPage(result);
			JSONArray partialData = result.getJSONArray("data");

			for (int i = 0; i < partialData.length(); i++) {
				JSONObject group = partialData.getJSONObject(i);
				resultData.put(group);
			}

		}

		result.put("data", resultData);

		return result;
	}

	private boolean addUserToGroup(String uid, String gid){
		String uri = GRAPH_API_BASE_URI + SLASH + gid + SLASH + "members";
		Map<String, String> formData = Collections.singletonMap("member", uid);

		LOGGER.info("addUserToGroup: {0}", uri);
		LOGGER.info("Adding user {0} to group: {1}", uid, gid);

		HttpPost httpPost = null;
		try{
			httpPost = buildHttpPost(uri, new JSONObject(formData));
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("No user profile was found for user ID: {0}", uri);
			return false;
		}

		String responseString = executeRequest(httpPost);

		if (responseString != null && !responseString.isEmpty()) {
			LOGGER.info("Adding user to a group was successful");
			return true;
		}

		LOGGER.error("User {0} was not added to group: {1}", uid, gid);
		return false;
	}


	private boolean deleteUserFromGroup(String uid, String gid){
		int groupMembers = getGroupMembersCount(gid);
		if(groupMembers <= 1){
			LOGGER.info("User {0} in Group {1} is last member, adding admin to the group", uid, gid, groupMembers);
			addUserToGroup(firstAdminId, gid);
		}

		String uri = GRAPH_API_BASE_URI + SLASH + gid + SLASH + "members" + SLASH + uid;
		HttpDelete httpDelete = buildHttpDelete(uri);
		String responseString = executeRequest(httpDelete);

		if (responseString != null && !responseString.isEmpty()) {
			LOGGER.info("Deletion of user from a group was successful");
			return true;
		}

		LOGGER.error("Deletion of user from group error: {0}", responseString);
		return false;
	}

	private int getGroupMembersCount(String gid) {
		String uri = GRAPH_API_BASE_URI + SLASH + gid + SLASH + "members";
		LOGGER.info("getGroupMembersCount url: {0}", uri);
		HttpGet httpGet = buildHttpGet(uri);
		String responseString = executeRequest(httpGet);

		if (responseString != null && !responseString.isEmpty()) {
			JSONObject jsonObject = new JSONObject(responseString);
			return jsonObject.getJSONArray("data").length();
		}

		return 0;
	}

	private String getFirstAdminId() {
		String uri = GRAPH_API_BASE_URI + SLASH + communityId + SLASH + "?fields=admins";
		LOGGER.info("getFirstAdminId url: {0}", uri);
		HttpGet httpGet = buildHttpGet(uri);
		String responseString = executeRequest(httpGet);

		if (responseString != null && !responseString.isEmpty()) {
			JSONObject jsonObject = new JSONObject(responseString);

			if(!jsonObject.has("admins")){
				return null;
			}

			JSONObject admins = jsonObject.getJSONObject("admins");

			if(!admins.has("data")){
				return null;
			}

			JSONArray adminsArray = admins.getJSONArray("data");

			if(adminsArray.length() == 0){
				return null;
			}

			JSONObject firstAdmin = adminsArray.getJSONObject(0);

			LOGGER.info("First admin (fallback) - {0}", firstAdmin.getString("name"));

			return firstAdmin.getString("id");
		}

		return null;
	}

	/** Get current user attribute values
     * 
     * @param uri   GET URL
     * @return JSON output of GET User methog
     */
    private JSONObject getCurrentUserData(String uri) {
        LOGGER.info("getCurrentUserData url: {0}", uri);
        HttpGet httpGet = buildHttpGet(uri);
		String responseString = executeRequest(httpGet);

		if (responseString != null && !responseString.isEmpty()) {

			return new JSONObject(responseString);
		}

		LOGGER.error("No user profile was found for user ID: {0}", uri);
		return null;
    }

	private JSONObject getUsersPage(int startingIndex, String uri){
		uri = uri + "?startIndex=" + startingIndex + "&count=100";
		LOGGER.info("Get Users page url: {0}", uri);

		HttpGet httpGet = buildHttpGet(uri);

		String responseString = executeRequest(httpGet);

		if (responseString != null && !responseString.isEmpty()) {
			return new JSONObject(responseString);
		}

		LOGGER.error("Failed getUsersPage: {0}", uri);
		return null;
	}

    private String executeRequest(HttpUriRequest request){
		try (CloseableHttpResponse response = (CloseableHttpResponse) httpClient.execute(request)) {
			HttpEntity entity = response.getEntity();
			String responseString;
			if (entity != null) {
				responseString = EntityUtils.toString(entity);
			} else {
				responseString = "";
			}

			int statusCode = response.getStatusLine().getStatusCode();
			LOGGER.info("Schema query status code: {0}", statusCode);
			if (statusCode >= 200 && statusCode < 300) {

				if (!responseString.isEmpty()) {
					return responseString;
				} else {
					LOGGER.error("Response is empty");
					return null;
				}
			}
			LOGGER.error("HTTP Failed {0} - {1}", statusCode, responseString);
			return null;
		} catch (ClientProtocolException e) {
			LOGGER.error(
					"An protocol exception has occurred while in the process of querying the provider Schemas resource object. Possible mismatch in interpretation of the HTTP specification: {0}",
					e.getLocalizedMessage());
			LOGGER.info(
					"An protocol exception has occurred while in the process of querying the provider Schemas resource object. Possible mismatch in interpretation of the HTTP specification: {0}",
					e);
			throw new ConnectorException(
					"An protocol exception has occurred while in the process of querying the provider Schemas resource object. Possible mismatch in interpretation of the HTTP specification",
					e);
		} catch (IOException e) {

			StringBuilder errorBuilder = new StringBuilder(
					"An error has occurred while processing the http response. Occurrence in the process of querying the provider Schemas resource object");

			if ((e instanceof SocketTimeoutException || e instanceof NoRouteToHostException)) {

				errorBuilder.insert(0, "The connection timed out. ");

				throw new OperationTimeoutException(errorBuilder.toString(), e);
			} else {

				LOGGER.error(
						"An error has occurred while processing the http response. Occurrence in the process of querying the provider Schemas resource object: {0}",
						e.getLocalizedMessage());
				LOGGER.info(
						"An error has occurred while processing the http response. Occurrence in the process of querying the provider Schemas resource object: {0}",
						e);

				throw new ConnectorIOException(errorBuilder.toString(), e);
			}
		}
	}

	private JSONObject getUsersFormOtherPages(JSONObject users, String uri, int startIndex) {
		JSONArray resources = users.getJSONArray(RESOURCES);
		do {
			JSONObject result = getUsersPage(startIndex + 1, uri);
			startIndex = getNextStartIndex(result);

			if(result != null && result.has(RESOURCES)){
				for (int i = 0; i < result.getJSONArray(RESOURCES).length(); i++) {
					JSONObject user = result.getJSONArray(RESOURCES).getJSONObject(i);
					resources.put(user);
				}
			}

		} while(startIndex != 0);

		users.put(RESOURCES, resources);

		return users;
	}


	private JSONObject populateUserJsonWithGroup(JSONObject user) {
		String uid = String.valueOf(user.getLong(ID));
		JSONObject userGroups = getUserGroups(uid);

		int amountOfResources = userGroups.getJSONArray("data").length();
		JSONArray groupsFormatted = new JSONArray();

		for (int i = 0; i < amountOfResources; i++) {
			JSONObject group = userGroups.getJSONArray("data").getJSONObject(i);

			String gid = String.valueOf(group.getLong(ID));
			groupsFormatted.put(gid);
		}

		user.put("groups", groupsFormatted);
		LOGGER.info("User populated: {0}", user.toString(1));

		return user;
	}


	private int getNextStartIndex(JSONObject jsonObject){
		if (jsonObject != null && jsonObject.has(STARTINDEX) && jsonObject.has(TOTALRESULTS) && jsonObject.has(ITEMSPERPAGE)) {
			int totalResults = (int) jsonObject.get(TOTALRESULTS);
			int startIndex = (int) jsonObject.get(STARTINDEX);
			int itemsPerPage = (int) jsonObject.get(ITEMSPERPAGE);
			int remainingResult = totalResults - (startIndex - 1) - itemsPerPage;

			if (remainingResult <= 0) {
				return 0;

			}

			return startIndex + itemsPerPage;
		}
		return 0;
	}


	private JSONObject getGroups(){
		JSONObject result = getGroupsPage("");
		JSONArray resultData = result.getJSONArray("data");

		String nextPage = getNextPage(result);
		while(nextPage != null){
			result = getGroupsPage(nextPage);
			nextPage = getNextPage(result);
			JSONArray partialData = result.getJSONArray("data");

			for (int i = 0; i < partialData.length(); i++) {
				JSONObject group = partialData.getJSONObject(i);
				resultData.put(group);
			}

		}

		result.put("data", resultData);

		return result;
	}

	private String getNextPage(JSONObject result){
		if(!result.has("paging")){
			return null;
		}
		JSONObject part = result.getJSONObject("paging");

		if(!part.has("cursors")){
			return null;
		}
		part = part.getJSONObject("cursors");

		if(!part.has("after")){
			return null;
		}
		return part.getString("after");
	}
    
    /** 
     * Method to return mandatory attributes for udate operation on workplace
     * @return map of mandatory attributes
     */    
    /** 
     * Method to return mandatory attributes for udate operation on workplace
     * @return map of mandatory attributes
     */
    private Map<String, String> getMandatoryAttributes() {
        Map<String, String> mandatoryAttributes = new HashMap<String, String>();
        mandatoryAttributes.put(SCHEMAS, SCHEMAS);
        mandatoryAttributes.put(USERNAME, USERNAME);
        mandatoryAttributes.put(NAME, NAME);
        mandatoryAttributes.put(ACTIVE, ACTIVE);
        return mandatoryAttributes;
    }
    /**
     * Method to inject into JSON mandatory user attributes 
     * @param jsonObjectINPUT - JSON object that should be injected by mandatory attributes
     * @param jsonUserOnResource - user Profile outbut JSON object
     * @param mandatoryAttributes - mandatory attributes to inject
     * @return  - injected JSON object
     * @throws Exception Mandatory attribute is missing in user Profile 
     */
    private JSONObject getMissingMandatoryAttributes(JSONObject jsonObjectINPUT, JSONObject jsonUserOnResource, Map<String, String> mandatoryAttributes) throws Exception {
        JSONObject returnJson = jsonObjectINPUT;
        Iterator<String> attributesIt = mandatoryAttributes.keySet().iterator();
        while (attributesIt.hasNext()) {
            String attribute = attributesIt.next();
            if (!returnJson.has(attribute)) {
                if (jsonUserOnResource.has(attribute)) {
                    Object attributeValue = jsonUserOnResource.get(attribute);
                    returnJson.put(attribute, attributeValue);
                } else {
                    LOGGER.error("Mandatory attribute is missing in user Profile JSON output: {0}",attribute);
                    throw new Exception("Mandatory attribute is missing in user Profile JSON output: " + attribute);
                }
            }
        }        
        return returnJson;
    }
    
    /** Normalize JSON oject in both way. 
     * to IDM direction: 
     * replace schema name of complex attribute with simple schema name e.g "urn:scim:schemas:extension:facebook:starttermdates:1.0" => "extensionstarttermdates"; 
     * the native manager attribute has JSON type so method convert JSON type attribute to long type e.g. "manager": {"managerId": 100033272841929} => "manager":  100033272841929
     * 
     * to Resoure direction:
     * replace simple schema name to complex name e.g. "extensionstarttermdates"  =>  "urn:scim:schemas:extension:facebook:starttermdates:1.0"; 
     * the native manager attribute has JSON type so method convert long type of attribute to JSON type e.g.  "manager":  100033272841929 => "manager": {"managerId": 100033272841929}
     * 
     * @param jsonObject
     * @return 
     */
    private JSONObject normalizeJSON(JSONObject jsonObject) {
        LOGGER.info("normalizeJSON start");
        if (jsonObject.has(ENTERPRISE)) {
            Object jsonVal = jsonObject.get(ENTERPRISE);
            JSONObject entrps = new JSONObject(jsonVal.toString());
            if (entrps.has(MANAGER)) {
                Map<String, Object> map = new HashMap<String, Object>();
                Object managerIdVal=null;
                if(entrps.isNull(MANAGER) || entrps.get(MANAGER).toString().isEmpty()){
                map.put(MANAGERID, JSONObject.NULL);
                } else{
                managerIdVal = entrps.getLong(MANAGER);
                map.put(MANAGERID, managerIdVal);
                }
                JSONObject managerValue = new JSONObject(map);
                entrps.remove(MANAGER);
                entrps.put(MANAGER, managerValue);
            }
            jsonObject.remove(ENTERPRISE);
            jsonObject.put(ENTERPRISEVALUE, entrps);
        } else if (jsonObject.has(ENTERPRISEVALUE)) {            
            Object jsonVal = jsonObject.get(ENTERPRISEVALUE);
            JSONObject entrps = new JSONObject(jsonVal.toString());
            LOGGER.info("entrps={0}",entrps);
            if (entrps.has(MANAGER)) {
                JSONObject managerVal = new JSONObject(entrps.get(MANAGER).toString());
                Object managerIdVal = managerVal.get(MANAGERID);
                entrps.remove(MANAGER);
                LOGGER.info("managerIdVal={0}",managerIdVal);
                entrps.put(MANAGER, managerIdVal);
            }
            jsonObject.remove(ENTERPRISEVALUE);
            jsonObject.put(ENTERPRISE, entrps);
        }
        if (jsonObject.has(STARTTERMDATES)) {
            Object jsonVal = jsonObject.get(STARTTERMDATES);
            jsonObject.remove(STARTTERMDATES);
            jsonObject.put(STARTTERMDATESVALUE, jsonVal);
        } else if (jsonObject.has(STARTTERMDATESVALUE)) {
            Object jsonVal = jsonObject.get(STARTTERMDATESVALUE);
            jsonObject.remove(STARTTERMDATESVALUE);
            jsonObject.put(STARTTERMDATES, jsonVal);
        }
        return jsonObject;
    }
    
    /** Call Normalize method for RESOURCES JSONArray object
     * 
     * @param jsonObject - input JSON object
     * @return Normalized JSON object
     */
    private JSONObject normalizeJSONFullRecon(JSONObject jsonObject){            
            if(jsonObject.has(RESOURCES) && jsonObject.has(STARTINDEX) && jsonObject.has(TOTALRESULTS) && jsonObject.has(ITEMSPERPAGE)){
                JSONArray outpuResourcesArray = new JSONArray();
                JSONArray resources = jsonObject.getJSONArray(RESOURCES);                                
                for(int i=0; i < resources.length(); i++){
                    JSONObject resource = new JSONObject(resources.get(i).toString());
                    resource=normalizeJSON(resource);
                    outpuResourcesArray.put(resource);
                    }
                jsonObject.remove(RESOURCES);
                jsonObject.put(RESOURCES, outpuResourcesArray);                
        }
               return jsonObject; 
    } 

}
