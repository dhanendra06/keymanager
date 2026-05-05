package io.mosip.kernel.signature.controller;

import io.mosip.kernel.signature.dto.*;
import io.mosip.kernel.signature.service.SignatureServicev2;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseFilter;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.signatureutil.model.SignatureResponse;
import io.mosip.kernel.keymanagerservice.logger.KeymanagerLogger;
import io.mosip.kernel.signature.service.SignatureService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 *
 * @author Uday Kumar
 * @since 1.0.0
 *
 */
@SuppressWarnings("java:S5122") // Need CrossOrigin access for all the APIs, added to ignore in sonarCloud Security hotspots.
@RestController
@CrossOrigin
@Tag(name = "signaturecontroller", description = "Operation related to signature")
public class SignatureController {

	private static final Logger LOGGER = KeymanagerLogger.getLogger(SignatureController.class);

	/**
	 * Crypto signature Service field with functions related to signature
	 */
	@Autowired
	SignatureService service;

	@Autowired
	SignatureServicev2 serviceV2;

	/**
	 * Function to sign response
	 *
	 * @param requestDto {@link SignRequestDto} having required fields.
	 * @return The {@link SignatureResponse}
	 */
	@Operation(summary = "Function to sign response", description = "Function to sign response", tags = {
			"signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostsign())")
	@PostMapping(value = "/sign")
	@Deprecated
	public ResponseWrapper<SignResponseDto> sign(@RequestBody @Valid RequestWrapper<SignRequestDto> requestDto) {
		long startTime = System.currentTimeMillis();
		SignatureResponse signatureResponse = service.sign(requestDto.getRequest());
		SignResponseDto signResponse = new SignResponseDto();
		signResponse.setTimestamp(signatureResponse.getTimestamp());
		signResponse.setSignature(signatureResponse.getData());
		ResponseWrapper<SignResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signResponse);
		LOGGER.info("PERF", "SignatureController", "sign",
				"Perf_SignatureController_sign timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}

	@Operation(summary = "Function to validate signature", description = "Function to validate signature", tags = {
			"signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN')")
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostvalidate())")
	@PostMapping(value = "/validate")
	@Deprecated
	public ResponseWrapper<ValidatorResponseDto> validate(
			@RequestBody @Valid RequestWrapper<TimestampRequestDto> timestampRequestDto) {
		long startTime = System.currentTimeMillis();
		ResponseWrapper<ValidatorResponseDto> response = new ResponseWrapper<>();
		response.setResponse(service.validate(timestampRequestDto.getRequest()));
		LOGGER.info("PERF", "SignatureController", "validate",
				"Perf_SignatureController_validate timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}

	@Operation(summary = "Function to sign PDF", description = "Function to sign PDF", tags = { "signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostpdfsign())")
	@PostMapping("/pdf/sign")
	public ResponseWrapper<SignatureResponseDto> signPDF(
			@RequestBody @Valid RequestWrapper<PDFSignatureRequestDto> signatureResponseDto) {
		long startTime = System.currentTimeMillis();
		ResponseWrapper<SignatureResponseDto> response = new ResponseWrapper<>();
		response.setResponse(service.signPDF(signatureResponseDto.getRequest()));
		LOGGER.info("PERF", "SignatureController", "signPDF",
				"Perf_SignatureController_signPDF timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}

	/**
	 * Function to do JSON Web Signature(JWS) for the input data using RS256 algorithm
	 *
	 * @param requestDto {@link JWTSignatureRequestDto} having required fields.
	 * @return The {@link JWTSignatureResponseDto}
	 */
	@Operation(summary = "TFunction to JWT sign datas", description = "Function to JWT sign data", tags = {
			"signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostjwtsign())")
	@PostMapping(value = "/jwtSign")
	public ResponseWrapper<JWTSignatureResponseDto> jwtSign(
			@RequestBody @Valid RequestWrapper<JWTSignatureRequestDto> requestDto) {
		long startTime = System.currentTimeMillis();
		JWTSignatureResponseDto signatureResponse = service.jwtSign(requestDto.getRequest());
		ResponseWrapper<JWTSignatureResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		LOGGER.info("PERF", "SignatureController", "jwtSign",
				"Perf_SignatureController_jwtSign timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}

	/**
	 * Function to JWT Signature verification
	 *
	 * @param requestDto {@link JWTSignatureVerifyRequestDto} having required
	 *                   fields.
	 * @return The {@link JWTSignatureVerifyResponseDto}
	 */
	@Operation(summary = "Function to JWT Signature verification", description = "Function to JWT Signature verification", tags = {
			"signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostjwtverify())")
	@PostMapping(value = "/jwtVerify")
	public ResponseWrapper<JWTSignatureVerifyResponseDto> jwtVerify(
			@RequestBody @Valid RequestWrapper<JWTSignatureVerifyRequestDto> requestDto) {
		long startTime = System.currentTimeMillis();
		JWTSignatureVerifyResponseDto signatureResponse = service.jwtVerify(requestDto.getRequest());
		ResponseWrapper<JWTSignatureVerifyResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		LOGGER.info("PERF", "SignatureController", "jwtVerify",
				"Perf_SignatureController_jwtVerify timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}

	/**
	 * Function to do JSON Web Signature(JWS) for the input data using input algorithm. Default Algorithm PS256.
	 *
	 * @param requestDto {@link JWTSignatureRequestDto} having required fields.
	 * @return The {@link JWTSignatureResponseDto}
	 */
	@Operation(summary = "Function to do JSON Web Signature(JWS) for the input data using input algorithm. Default Algorithm PS256.",
			description = "Function to JWT sign data", tags = { "signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostjwssign())")
	@PostMapping(value = "/jwsSign")
	public ResponseWrapper<JWTSignatureResponseDto> jwsSign(
			@RequestBody @Valid RequestWrapper<JWSSignatureRequestDto> requestDto) {
		long startTime = System.currentTimeMillis();
		JWTSignatureResponseDto signatureResponse = service.jwsSign(requestDto.getRequest());
		ResponseWrapper<JWTSignatureResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		LOGGER.info("PERF", "SignatureController", "jwsSign",
				"Perf_SignatureController_jwsSign timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}

	/**
	 * Function to do Signature input raw data using input algorithm. Default Algorithm PS256.
	 *
	 * @param requestDto {@link JWTSignatureRequestDto} having required fields.
	 * @return The {@link JWTSignatureResponseDto}
	 */
	@Operation(summary = "Function to do Signature for the input raw data using input algorithm. Default Algorithm PS256.",
			description = "Function to sign raw data", tags = { "signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostsignv2())")
	@PostMapping(value = "/signV2")
	public ResponseWrapper<SignResponseDto> signV2(
			@RequestBody @Valid RequestWrapper<SignRequestDtoV2> requestDto) {
		long startTime = System.currentTimeMillis();
		SignResponseDto signatureResponse = serviceV2.signv2(requestDto.getRequest());
		ResponseWrapper<SignResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		LOGGER.info("PERF", "SignatureController", "signV2",
				"Perf_SignatureController_signV2 timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}

	/**
	 * Function to do Signature input raw data using input algorithm. Default Algorithm PS256.
	 *
	 * @param requestDto {@link JWTSignatureRequestDto} having required fields.
	 * @return The {@link JWTSignatureResponseDto}
	 */
	@Operation(summary = "Function to do Signature for the input raw data using input algorithm. Default Algorithm PS256.",
			description = "Function to sign raw data", tags = { "signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostsignrawdata())")
	@PostMapping(value = "/signRawData")
	public ResponseWrapper<SignResponseDtoV2> signRawData(
			@RequestBody @Valid RequestWrapper<SignRequestDtoV2> requestDto) {
		long startTime = System.currentTimeMillis();
		SignResponseDtoV2 signatureResponse = serviceV2.rawSign(requestDto.getRequest());
		ResponseWrapper<SignResponseDtoV2> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		LOGGER.info("PERF", "SignatureController", "signRawData",
				"Perf_SignatureController_signRawData timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}

	/**
	 * Function to do JSON Web Signature(JWS) for the input data using MOSIP supported Signature algorithm
	 *
	 * @param requestDto {@link JWTSignatureRequestDto} having required fields.
	 * @return The {@link JWTSignatureResponseDto}
	 */
	@Operation(summary = "TFunction to JWT sign datas", description = "Function to JWT sign data", tags = {
			"signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostjwtsign())")
	@PostMapping(value = "/jwtSign/v2")
	public ResponseWrapper<JWTSignatureResponseDto> jwtSignV2(
			@RequestBody @Valid RequestWrapper<JWTSignatureRequestDtoV2> requestDto) {
		long startTime = System.currentTimeMillis();
		JWTSignatureResponseDto signatureResponse = service.jwtSignV2(requestDto.getRequest());
		ResponseWrapper<JWTSignatureResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		LOGGER.info("PERF", "SignatureController", "jwtSignV2",
				"Perf_SignatureController_jwtSignV2 timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}

	/**
	 * Function to do JSON Web Signature(JWS) for the input data using input algorithm. Default Algorithm PS256.
	 *
	 * @param requestDto {@link JWTSignatureRequestDto} having required fields.
	 * @return The {@link JWTSignatureResponseDto}
	 */
	@Operation(summary = "Function to do JSON Web Signature(JWS) for the input data using input algorithm. Default Algorithm PS256.",
			description = "Function to JWT sign data", tags = { "signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostjwssign())")
	@PostMapping(value = "/jwsSign/v2")
	public ResponseWrapper<JWTSignatureResponseDto> jwsSignV2(
			@RequestBody @Valid RequestWrapper<JWSSignatureRequestDtoV2> requestDto) {
		long startTime = System.currentTimeMillis();
		JWTSignatureResponseDto signatureResponse = service.jwsSignV2(requestDto.getRequest());
		ResponseWrapper<JWTSignatureResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		LOGGER.info("PERF", "SignatureController", "jwsSignV2",
				"Perf_SignatureController_jwsSignV2 timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}

	/**
	 * Function to JWT Signature verification
	 *
	 * @param requestDto {@link JWTSignatureVerifyRequestDto} having required fields.
	 * @return The {@link JWTSignatureVerifyResponseDto}
	 */
	@Operation(summary = "Function to JWT Signature verification", description = "Function to JWT Signature verification", tags = {
			"signaturecontroller" })
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Success or you may find errors in error array in response"),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(schema = @Schema(hidden = true))),
			@ApiResponse(responseCode = "404", description = "Not Found", content = @Content(schema = @Schema(hidden = true))) })
	//@PreAuthorize("hasAnyRole('ZONAL_ADMIN','GLOBAL_ADMIN','INDIVIDUAL','ID_AUTHENTICATION', 'REGISTRATION_ADMIN', 'REGISTRATION_SUPERVISOR', 'REGISTRATION_OFFICER', 'REGISTRATION_PROCESSOR','PRE_REGISTRATION_ADMIN','RESIDENT')")
	@ResponseFilter
	@PreAuthorize("hasAnyRole(@signAuthRoles.getPostjwtverify())")
	@PostMapping(value = "/jwtVerify/v2")
	public ResponseWrapper<JWTSignatureVerifyResponseDto> jwtVerifyV2(
			@RequestBody @Valid RequestWrapper<JWTSignatureVerifyRequestDto> requestDto) {
		long startTime = System.currentTimeMillis();
		JWTSignatureVerifyResponseDto signatureResponse = service.jwtVerifyV2(requestDto.getRequest());
		ResponseWrapper<JWTSignatureVerifyResponseDto> response = new ResponseWrapper<>();
		response.setResponse(signatureResponse);
		LOGGER.info("PERF", "SignatureController", "jwtVerifyV2",
				"Perf_SignatureController_jwtVerifyV2 timeTaken: " + (System.currentTimeMillis() - startTime) + "ms");
		return response;
	}
}