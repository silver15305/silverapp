/**
 * Payment Service
 * Handles payments using WeChat Pay and Alipay
 * China-compatible payment services
 */

const crypto = require('crypto');
const axios = require('axios');
const xml2js = require('xml2js');
const config = require('../config/env');
const { logger } = require('../config/logger');

/**
 * Payment Service Class
 */
class PaymentService {
  constructor() {
    this.wechatConfig = config.wechat;
    this.alipayConfig = config.alipay;
    this.isInitialized = false;
    this.init();
  }

  /**
   * Initialize payment service
   */
  init() {
    try {
      if (this.wechatConfig.appId && this.wechatConfig.mchId) {
        logger.info('WeChat Pay service initialized');
      }

      if (this.alipayConfig.appId && this.alipayConfig.privateKey) {
        logger.info('Alipay service initialized');
      }

      this.isInitialized = true;
      logger.info('Payment service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize payment service:', error);
    }
  }

  /**
   * Check if payment service is available
   * @returns {boolean} Service availability
   */
  isAvailable() {
    return this.isInitialized && (
      (this.wechatConfig.appId && this.wechatConfig.mchId) ||
      (this.alipayConfig.appId && this.alipayConfig.privateKey)
    );
  }

  /**
   * Generate WeChat Pay signature
   * @param {Object} params - Parameters to sign
   * @returns {string} Signature
   */
  generateWechatSignature(params) {
    const sortedKeys = Object.keys(params).sort();
    const stringA = sortedKeys
      .filter(key => params[key] !== '' && key !== 'sign')
      .map(key => `${key}=${params[key]}`)
      .join('&');
    
    const stringSignTemp = `${stringA}&key=${this.wechatConfig.apiKey}`;
    return crypto.createHash('md5').update(stringSignTemp, 'utf8').digest('hex').toUpperCase();
  }

  /**
   * Create WeChat Pay unified order
   * @param {Object} orderData - Order data
   * @returns {Promise<Object>} Order result
   */
  async createWechatOrder(orderData) {
    try {
      const {
        outTradeNo,
        totalFee,
        body,
        openid,
        tradeType = 'JSAPI',
        notifyUrl
      } = orderData;

      const params = {
        appid: this.wechatConfig.appId,
        mch_id: this.wechatConfig.mchId,
        nonce_str: crypto.randomBytes(16).toString('hex'),
        body: body,
        out_trade_no: outTradeNo,
        total_fee: totalFee,
        spbill_create_ip: '127.0.0.1',
        notify_url: notifyUrl,
        trade_type: tradeType,
        openid: openid
      };

      params.sign = this.generateWechatSignature(params);

      const builder = new xml2js.Builder({ rootName: 'xml', headless: true });
      const xml = builder.buildObject(params);

      const response = await axios.post(
        'https://api.mch.weixin.qq.com/pay/unifiedorder',
        xml,
        {
          headers: {
            'Content-Type': 'application/xml'
          }
        }
      );

      const parser = new xml2js.Parser({ explicitArray: false });
      const result = await parser.parseStringPromise(response.data);

      if (result.xml.return_code === 'SUCCESS' && result.xml.result_code === 'SUCCESS') {
        logger.info('WeChat Pay order created successfully:', {
          outTradeNo,
          prepayId: result.xml.prepay_id
        });

        return {
          success: true,
          provider: 'wechat',
          prepayId: result.xml.prepay_id,
          codeUrl: result.xml.code_url,
          result: result.xml
        };
      } else {
        throw new Error(result.xml.err_code_des || result.xml.return_msg);
      }

    } catch (error) {
      logger.error('WeChat Pay order creation failed:', error);
      return {
        success: false,
        provider: 'wechat',
        error: error.message
      };
    }
  }

  /**
   * Generate Alipay signature
   * @param {Object} params - Parameters to sign
   * @returns {string} Signature
   */
  generateAlipaySignature(params) {
    const sortedKeys = Object.keys(params).sort();
    const stringA = sortedKeys
      .filter(key => params[key] !== '' && key !== 'sign')
      .map(key => `${key}=${params[key]}`)
      .join('&');

    const sign = crypto.createSign('RSA-SHA256');
    sign.update(stringA, 'utf8');
    return sign.sign(this.alipayConfig.privateKey, 'base64');
  }

  /**
   * Create Alipay order
   * @param {Object} orderData - Order data
   * @returns {Promise<Object>} Order result
   */
  async createAlipayOrder(orderData) {
    try {
      const {
        outTradeNo,
        totalAmount,
        subject,
        notifyUrl,
        returnUrl
      } = orderData;

      const params = {
        app_id: this.alipayConfig.appId,
        method: 'alipay.trade.page.pay',
        charset: 'utf-8',
        sign_type: 'RSA2',
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        version: '1.0',
        notify_url: notifyUrl,
        return_url: returnUrl,
        biz_content: JSON.stringify({
          out_trade_no: outTradeNo,
          total_amount: totalAmount,
          subject: subject,
          product_code: 'FAST_INSTANT_TRADE_PAY'
        })
      };

      params.sign = this.generateAlipaySignature(params);

      const queryString = Object.keys(params)
        .map(key => `${key}=${encodeURIComponent(params[key])}`)
        .join('&');

      const payUrl = `${this.alipayConfig.gateway}?${queryString}`;

      logger.info('Alipay order created successfully:', {
        outTradeNo,
        payUrl: payUrl.substring(0, 100) + '...'
      });

      return {
        success: true,
        provider: 'alipay',
        payUrl: payUrl,
        outTradeNo: outTradeNo
      };

    } catch (error) {
      logger.error('Alipay order creation failed:', error);
      return {
        success: false,
        provider: 'alipay',
        error: error.message
      };
    }
  }

  /**
   * Create payment order
   * @param {Object} orderData - Order data
   * @param {string} provider - Payment provider ('wechat' or 'alipay')
   * @returns {Promise<Object>} Order result
   */
  async createPaymentOrder(orderData, provider = 'wechat') {
    try {
      if (!this.isAvailable()) {
        throw new Error('Payment service not available');
      }

      let result;

      if (provider === 'wechat' && this.wechatConfig.appId) {
        result = await this.createWechatOrder(orderData);
      } else if (provider === 'alipay' && this.alipayConfig.appId) {
        result = await this.createAlipayOrder(orderData);
      } else {
        throw new Error('Invalid payment provider or not configured');
      }

      return result;

    } catch (error) {
      logger.error('Payment order creation failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Verify WeChat Pay callback
   * @param {string} xmlData - XML callback data
   * @returns {Object} Verification result
   */
  verifyWechatCallback(xmlData) {
    try {
      const parser = new xml2js.Parser({ explicitArray: false });
      const result = parser.parseStringSync(xmlData);
      const data = result.xml;

      const receivedSign = data.sign;
      delete data.sign;

      const calculatedSign = this.generateWechatSignature(data);

      const isValid = receivedSign === calculatedSign;

      logger.info('WeChat Pay callback verification:', {
        isValid,
        outTradeNo: data.out_trade_no,
        transactionId: data.transaction_id
      });

      return {
        isValid,
        data,
        outTradeNo: data.out_trade_no,
        transactionId: data.transaction_id,
        totalFee: data.total_fee
      };

    } catch (error) {
      logger.error('WeChat Pay callback verification failed:', error);
      return {
        isValid: false,
        error: error.message
      };
    }
  }

  /**
   * Verify Alipay callback with enhanced security
   * @param {Object} params - Callback parameters
   * @returns {Object} Verification result
   */
  verifyAlipayCallback(params) {
    try {
      const receivedSign = params.sign;
      delete params.sign;
      delete params.sign_type;

      const sortedKeys = Object.keys(params).sort();
      const stringA = sortedKeys
        .map(key => `${key}=${params[key]}`)
        .join('&');

      const verify = crypto.createVerify('RSA-SHA256');
      verify.update(stringA, 'utf8');
      const isValid = verify.verify(this.alipayConfig.publicKey, receivedSign, 'base64');

      logger.info('Alipay callback verification:', {
        isValid,
        outTradeNo: params.out_trade_no,
        tradeNo: params.trade_no
      });

      // Enhanced verification: Query Alipay server to confirm transaction
      if (isValid) {
        this.verifyAlipayTransactionWithServer(params.out_trade_no, params.trade_no)
          .then(serverVerification => {
            if (!serverVerification.success) {
              logger.warn('Alipay server verification failed:', {
                outTradeNo: params.out_trade_no,
                tradeNo: params.trade_no,
                error: serverVerification.error
              });
            } else {
              logger.info('Alipay server verification successful:', {
                outTradeNo: params.out_trade_no,
                tradeNo: params.trade_no,
                serverStatus: serverVerification.tradeStatus
              });
            }
          })
          .catch(error => {
            logger.error('Alipay server verification error:', error);
          });
      }

      return {
        isValid,
        data: params,
        outTradeNo: params.out_trade_no,
        tradeNo: params.trade_no,
        totalAmount: params.total_amount
      };

    } catch (error) {
      logger.error('Alipay callback verification failed:', error);
      return {
        isValid: false,
        error: error.message
      };
    }
  }

  /**
   * Verify Alipay transaction with server (enhanced security)
   * @param {string} outTradeNo - Order trade number
   * @param {string} tradeNo - Alipay trade number
   * @returns {Promise<Object>} Server verification result
   */
  async verifyAlipayTransactionWithServer(outTradeNo, tradeNo) {
    try {
      const params = {
        app_id: this.alipayConfig.appId,
        method: 'alipay.trade.query',
        charset: 'utf-8',
        sign_type: 'RSA2',
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        version: '1.0',
        biz_content: JSON.stringify({
          out_trade_no: outTradeNo,
          trade_no: tradeNo
        })
      };

      params.sign = this.generateAlipaySignature(params);

      const response = await axios.post(
        this.alipayConfig.gateway,
        new URLSearchParams(params),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: 10000 // 10 second timeout
        }
      );

      const result = JSON.parse(response.data);
      const queryResponse = result.alipay_trade_query_response;

      if (queryResponse.code === '10000') {
        // Verify that the transaction details match
        const isValidTransaction = 
          queryResponse.out_trade_no === outTradeNo &&
          queryResponse.trade_no === tradeNo &&
          queryResponse.trade_status === 'TRADE_SUCCESS';

        return {
          success: isValidTransaction,
          tradeStatus: queryResponse.trade_status,
          data: queryResponse,
          verified: isValidTransaction
        };
      } else {
        return {
          success: false,
          error: queryResponse.sub_msg || queryResponse.msg,
          code: queryResponse.code
        };
      }

    } catch (error) {
      logger.error('Alipay server verification failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Query WeChat Pay order status
   * @param {string} outTradeNo - Order number
   * @returns {Promise<Object>} Order status
   */
  async queryWechatOrder(outTradeNo) {
    try {
      const params = {
        appid: this.wechatConfig.appId,
        mch_id: this.wechatConfig.mchId,
        out_trade_no: outTradeNo,
        nonce_str: crypto.randomBytes(16).toString('hex')
      };

      params.sign = this.generateWechatSignature(params);

      const builder = new xml2js.Builder({ rootName: 'xml', headless: true });
      const xml = builder.buildObject(params);

      const response = await axios.post(
        'https://api.mch.weixin.qq.com/pay/orderquery',
        xml,
        {
          headers: {
            'Content-Type': 'application/xml'
          }
        }
      );

      const parser = new xml2js.Parser({ explicitArray: false });
      const result = await parser.parseStringPromise(response.data);

      return {
        success: result.xml.return_code === 'SUCCESS',
        data: result.xml,
        tradeState: result.xml.trade_state
      };

    } catch (error) {
      logger.error('WeChat Pay order query failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Query Alipay order status
   * @param {string} outTradeNo - Order number
   * @returns {Promise<Object>} Order status
   */
  async queryAlipayOrder(outTradeNo) {
    try {
      const params = {
        app_id: this.alipayConfig.appId,
        method: 'alipay.trade.query',
        charset: 'utf-8',
        sign_type: 'RSA2',
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        version: '1.0',
        biz_content: JSON.stringify({
          out_trade_no: outTradeNo
        })
      };

      params.sign = this.generateAlipaySignature(params);

      const response = await axios.post(
        this.alipayConfig.gateway,
        new URLSearchParams(params),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      const result = JSON.parse(response.data);

      return {
        success: result.alipay_trade_query_response.code === '10000',
        data: result.alipay_trade_query_response,
        tradeStatus: result.alipay_trade_query_response.trade_status
      };

    } catch (error) {
      logger.error('Alipay order query failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Refund WeChat Pay order
   * @param {Object} refundData - Refund data
   * @returns {Promise<Object>} Refund result
   */
  async refundWechatOrder(refundData) {
    try {
      const {
        outTradeNo,
        outRefundNo,
        totalFee,
        refundFee,
        refundDesc
      } = refundData;

      const params = {
        appid: this.wechatConfig.appId,
        mch_id: this.wechatConfig.mchId,
        nonce_str: crypto.randomBytes(16).toString('hex'),
        out_trade_no: outTradeNo,
        out_refund_no: outRefundNo,
        total_fee: totalFee,
        refund_fee: refundFee,
        refund_desc: refundDesc
      };

      params.sign = this.generateWechatSignature(params);

      const builder = new xml2js.Builder({ rootName: 'xml', headless: true });
      const xml = builder.buildObject(params);

      const response = await axios.post(
        'https://api.mch.weixin.qq.com/secapi/pay/refund',
        xml,
        {
          headers: {
            'Content-Type': 'application/xml'
          }
        }
      );

      const parser = new xml2js.Parser({ explicitArray: false });
      const result = await parser.parseStringPromise(response.data);

      if (result.xml.return_code === 'SUCCESS' && result.xml.result_code === 'SUCCESS') {
        logger.info('WeChat Pay refund successful:', {
          outTradeNo,
          outRefundNo,
          refundId: result.xml.refund_id
        });

        return {
          success: true,
          provider: 'wechat',
          refundId: result.xml.refund_id,
          result: result.xml
        };
      } else {
        throw new Error(result.xml.err_code_des || result.xml.return_msg);
      }

    } catch (error) {
      logger.error('WeChat Pay refund failed:', error);
      return {
        success: false,
        provider: 'wechat',
        error: error.message
      };
    }
  }
}

// Create singleton instance
const paymentService = new PaymentService();

module.exports = paymentService;