/*
 * Copyright (c) 2023-2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.extension.identity.authenticator.duo.test;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.duo.DuoAuthenticator;
import org.wso2.carbon.identity.authenticator.duo.DuoAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.duo.internal.DuoServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test case for Mobile based 2nd factor Federated Authenticator.
 */
public class DuoAuthenticatorTest {

    private DuoAuthenticator duoAuthenticator;
    private AuthenticationContext context;
    private AutoCloseable closeable;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmService realmService;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private DuoServiceHolder serviceHolder;

    @Mock
    private AuthenticatorConfig authenticatorConfig;

    private MockedStatic<DuoServiceHolder> duoServiceHolderMock;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMock;
    private MockedStatic<FederatedAuthenticatorUtil> federatedAuthUtilMock;
    private MockedStatic<FrameworkUtils> frameworkUtilsMock;
    private MockedStatic<IdentityUtil> identityUtilMock;

    @BeforeMethod
    public void setUp() {

        closeable = MockitoAnnotations.openMocks(this);
        duoAuthenticator = spy(new TestableDuoAuthenticator());
        context = new AuthenticationContext();
        duoServiceHolderMock = mockStatic(DuoServiceHolder.class);
        duoServiceHolderMock.when(DuoServiceHolder::getInstance).thenReturn(serviceHolder);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        if (identityTenantUtilMock != null) {
            identityTenantUtilMock.close();
            identityTenantUtilMock = null;
        }
        if (federatedAuthUtilMock != null) {
            federatedAuthUtilMock.close();
            federatedAuthUtilMock = null;
        }
        if (frameworkUtilsMock != null) {
            frameworkUtilsMock.close();
            frameworkUtilsMock = null;
        }
        if (identityUtilMock != null) {
            identityUtilMock.close();
            identityUtilMock = null;
        }
        if (duoServiceHolderMock != null) {
            duoServiceHolderMock.close();
            duoServiceHolderMock = null;
        }
        closeable.close();
    }

    @Test(description = "Test case for canHandle() method true case.")
    public void testCanHandleTrue() {

        when(httpServletRequest.getParameter(DuoAuthenticatorConstants.DUO_STATE)).thenReturn("state");
        when(httpServletRequest.getParameter(DuoAuthenticatorConstants.DUO_CODE)).thenReturn("code");
        Assert.assertEquals(duoAuthenticator.canHandle(httpServletRequest), true);
    }

    @Test(description = "Test case for canHandle() method false case.")
    public void testCanHandleFalse() {

        when(httpServletRequest.getParameter(DuoAuthenticatorConstants.DUO_STATE)).thenReturn(null);
        when(httpServletRequest.getParameter(DuoAuthenticatorConstants.DUO_CODE)).thenReturn(null);
        Assert.assertEquals(duoAuthenticator.canHandle(httpServletRequest), false);
    }

    @Test(description = "Test case for getFriendlyName() method.")
    public void testGetFriendlyName() {

        Assert.assertEquals(duoAuthenticator.getFriendlyName(),
                DuoAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test(description = "Test case for getName() method.")
    public void testGetName() {

        Assert.assertEquals(duoAuthenticator.getName(),
                DuoAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    @Test(description = "Test case for retryAuthenticationEnabled() method.")
    public void testRetryAuthenticationEnabled() throws Exception {

        Assert.assertEquals(Optional.ofNullable(invokePrivateMethod("retryAuthenticationEnabled",
                new Class<?>[]{})).get(), true);
    }

    @Test(description = "Test case for getContextIdentifier() method.")
    public void testGetContextIdentifier() {

        when(httpServletRequest.getParameter(DuoAuthenticatorConstants.SESSION_DATA_KEY)).thenReturn("abc");
        Assert.assertEquals(duoAuthenticator.getContextIdentifier(httpServletRequest),
                "abc");
    }

    @Test(description = "Test case for getMobileClaimValue() method.")
    public void testGetMobileClaimValue() throws Exception {

        identityTenantUtilMock = mockStatic(IdentityTenantUtil.class);
        federatedAuthUtilMock = mockStatic(FederatedAuthenticatorUtil.class);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(-1234);
        when(serviceHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");
        authenticatedUser.setAuthenticatedSubjectIdentifier("admin@carbon.super");
        context.setProperty(DuoAuthenticatorConstants.AUTHENTICATED_USER, authenticatedUser);
        when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        DuoAuthenticatorConstants.MOBILE_CLAIM, null)).thenReturn("0771234565");
        Assert.assertEquals(invokePrivateMethod("getMobileClaimValue",
                new Class<?>[]{AuthenticationContext.class}, context), "0771234565");
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class}, description = "Test case for " +
            "getMobileClaimValue() method with exception")
    public void testGetMobileClaimValueWithException() throws Exception {

        identityTenantUtilMock = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(0);
        when(serviceHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        DuoAuthenticatorConstants.MOBILE_CLAIM, null)).thenReturn("0771234565");
        invokePrivateMethod("getMobileClaimValue",
                new Class<?>[]{AuthenticationContext.class}, context);
    }

    @Test(description = "Test case for checkStatusCode() with number mis match")
    public void testCheckStatusCodeWithNumberMismatch() throws Exception {

        frameworkUtilsMock = mockStatic(FrameworkUtils.class);
        identityUtilMock = mockStatic(IdentityUtil.class);
        ((TestableDuoAuthenticator) duoAuthenticator).setTestAuthenticatorConfig(authenticatorConfig);
        when(authenticatorConfig.getParameterMap()).thenReturn(new HashMap<>());
        context.setProperty(DuoAuthenticatorConstants.NUMBER_MISMATCH, true);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn
                (null);
        identityUtilMock.when(() -> IdentityUtil.getServerURL(DuoAuthenticatorConstants.DUO_DEFAULT_ERROR_PAGE, false,
                false)).thenReturn(DuoAuthenticatorConstants.DUO_DEFAULT_ERROR_PAGE);
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        invokePrivateMethod("checkStatusCode",
                new Class<?>[]{HttpServletResponse.class, AuthenticationContext.class},
                httpServletResponse, context);
        verify(httpServletResponse).sendRedirect(captor.capture());
        Assert.assertTrue(captor.getValue().contains(DuoAuthenticatorConstants.DuoErrors.ERROR_NUMBER_MISMATCH));
    }

    @Test(description = "Test case for getErrorPage() method")
    public void testGetErrorPage() throws Exception {

        frameworkUtilsMock = mockStatic(FrameworkUtils.class);
        identityUtilMock = mockStatic(IdentityUtil.class);
        ((TestableDuoAuthenticator) duoAuthenticator).setTestAuthenticatorConfig(authenticatorConfig);
        when(authenticatorConfig.getParameterMap()).thenReturn(new HashMap<>());
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn
                (null);
        Assert.assertNull(invokePrivateMethod("getErrorPage",
                new Class<?>[]{AuthenticationContext.class}, context));
    }

    @Test(description = "Test case for isValidPhoneNumber() method")
    public void testIsValidPhoneNumber() throws Exception {

        JSONObject jo = new JSONObject();
        jo.put("number", "0771234567");
        JSONArray jsonArray = new JSONArray();
        jsonArray.put(jo);
        Assert.assertEquals(Optional.ofNullable(invokePrivateMethod("isValidPhoneNumber",
                new Class<?>[]{AuthenticationContext.class, JSONArray.class, String.class},
                context, jsonArray, "0771234567")).get(), true);
    }

    @Test(description = "Test case for isValidPhoneNumber() method false")
    public void testIsValidPhoneNumberWithFalse() throws Exception {

        JSONObject jo = new JSONObject();
        jo.put("number", "");
        JSONArray jsonArray = new JSONArray();
        jsonArray.put(jo);
        Assert.assertEquals(Optional.ofNullable(invokePrivateMethod("isValidPhoneNumber",
                new Class<?>[]{AuthenticationContext.class, JSONArray.class, String.class},
                context, jsonArray, "0771234567")).get(), false);
    }

    @Test(description = "Test case for getConfigurationProperties() method.")
    public void testGetConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();
        Property duoHost = new Property();
        configProperties.add(duoHost);
        Property integrationKey = new Property();
        configProperties.add(integrationKey);
        Property adminIntegrationKey = new Property();
        configProperties.add(adminIntegrationKey);
        Property secretKey = new Property();
        configProperties.add(secretKey);
        Property adminSecretKey = new Property();
        configProperties.add(adminSecretKey);
        Property disableUserStoreDomain = new Property();
        configProperties.add(disableUserStoreDomain);
        Property disableTenantDomain = new Property();
        configProperties.add(disableTenantDomain);
        Assert.assertEquals(configProperties.size(), duoAuthenticator.getConfigurationProperties().size());
    }

    @Test(description = "Test case for isValidResponse() method.")
    public void testIsValidResponseTrue() throws Exception {

        String contextState = "ABC";
        String duoState = "ABC";
        Assert.assertTrue((Boolean) invokePrivateMethod("isValidResponse",
                new Class<?>[]{String.class, String.class}, contextState, duoState));
    }

    @Test(description = "Test case for isValidResponse() method.")
    public void testIsValidResponseFalse() throws Exception {

        String contextState = "ABC";
        String duoState = "abc";
        Assert.assertFalse((Boolean) invokePrivateMethod("isValidResponse",
                new Class<?>[]{String.class, String.class}, contextState, duoState));
    }

    /**
     * Invokes a private or protected method on the duoAuthenticator instance via reflection.
     *
     * @param methodName the method name
     * @param paramTypes the parameter types
     * @param args       the arguments
     * @return the method return value
     * @throws Exception if the method invocation fails
     */
    private Object invokePrivateMethod(String methodName, Class<?>[] paramTypes, Object... args) throws Exception {

        Method method = DuoAuthenticator.class.getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        try {
            return method.invoke(duoAuthenticator, args);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }

    /**
     * Testable subclass that exposes the protected getAuthenticatorConfig() method
     * for stubbing in tests.
     */
    private static class TestableDuoAuthenticator extends DuoAuthenticator {

        private AuthenticatorConfig testAuthenticatorConfig;

        void setTestAuthenticatorConfig(AuthenticatorConfig config) {

            this.testAuthenticatorConfig = config;
        }

        @Override
        protected AuthenticatorConfig getAuthenticatorConfig() {

            if (testAuthenticatorConfig != null) {
                return testAuthenticatorConfig;
            }
            return super.getAuthenticatorConfig();
        }
    }
}
